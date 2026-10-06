File ban đầu được đóng gói dạng `.wim` nên khả năng cao chứa dữ liệu ẩn dạng NTFS Alternate Data Stream (ADS).

```powershell
Get-Item .\PolyjuicePotion.txt -Stream *

```

<p align="center">

  <img src="img_assets/Pasted image 20261006080800.png">
</p>

Ta thấy một stream ẩn có tên `LordVoldemort` với độ dài 18 bytes

```powershell
Get-Content .\PolyjuicePotion.txt -Stream LordVoldemort

```

<p align="center">

  <img src="img_assets/Pasted image 20261006080943.png">
</p>

```c
__int64 __fastcall StartAddress(LPVOID lpThreadParameter)
{
  SOCKET v3; // rdi
  SOCKET v4; // rsi
  char *v5; // rcx
  unsigned __int64 v6; // rdx
  __int64 v7; // rax
  unsigned __int64 v8; // rax
  sockaddr name; // [rsp+20h] [rbp-2C8h] BYREF
  WSAData WSAData; // [rsp+30h] [rbp-2B8h] BYREF
  char buf[256]; // [rsp+1D0h] [rbp-118h] BYREF

  if ( WSAStartup(0x202u, &WSAData) )
    return 1;
  v3 = socket(2, 1, 6);
  if ( v3 == -1 )
    goto LABEL_18;
  name.sa_family = 2;
  *(_WORD *)name.sa_data = htons(31337u);
  inet_pton(2, "127.0.0.1", &name.sa_data[2]);
  if ( bind(v3, &name, 16) == -1 || listen(v3, 0x7FFFFFFF) == -1 )
  {
    closesocket(v3);
LABEL_18:
    WSACleanup();
    return 1;
  }
  v4 = accept(v3, 0, 0);
  if ( v4 != -1 )
  {
    memset(buf, 0, sizeof(buf));
    if ( recv(v4, buf, 255, 0) > 8 && !strncmp(buf, "OVERRIDE:", 9u) )
    {
      strncpy_s(*(char **)lpThreadParameter, *((_QWORD *)lpThreadParameter + 1), &buf[9], 0xFFFFFFFFFFFFFFFFuLL);
      v5 = *(char **)lpThreadParameter;
      v6 = 0;
      v7 = -1;
      do
        ++v7;
      while ( v5[v7] );
      if ( v7 )
      {
        do
        {
          v5[v6] ^= 0x33u;
          *(_BYTE *)(*(_QWORD *)lpThreadParameter + v6) += 5;
          v8 = -1;
          v5 = *(char **)lpThreadParameter;
          ++v6;
          do
            ++v8;
          while ( v5[v8] );
        }
        while ( v6 < v8 );
      }
    }
    closesocket(v4);
  }
  closesocket(v3);
  WSACleanup();
  return 0;
}

```

Chương trình tạo Thread 1 mở socket 127.0.0 port 31337 chờ nhận chuỗi `OVERRIDE:` , phía dưới lệnh chạy thread này có sleep 10 giây

<p align="center">

  <img src="img_assets/Pasted image 20261006081410.png">
</p>

<p align="center">

  <img src="img_assets/Pasted image 20261006081444.png">
</p>

Dùng sse khởi tạo mảng 256 phần tử trong `v28` rồi xáo trộn xong không sài.
`GetSystemInfo`, `GlobalMemoryStatusEx`, `GetTickCount` lấy ram, cpu và thời gian rồi ghép với chuỗi `"Telemetry_%u_%x"` (xong cũng không sài, không trả về hay ghi đè vào `lpThreadParamater`)

<p align="center">

  <img src="img_assets/Pasted image 20261006082317.png">
</p>

<p align="center">

  <img src="img_assets/Pasted image 20261006082329.png">
</p>

Đoạn này là logic quan trọng. Mặc định giá trị là 0 nên khối `if` này không bao giờ chạy, thử patch giá trị để chạy khối `if` thì ra được chuỗi:

<p align="center">

  <img src="img_assets/Pasted image 20261006082435.png">
</p>

check `unk_7FF664D06668` thì chỉ có đúng mỗi đoạn này xref tới, cũng có giả thuyết chương trình phân giải địa chỉ động ở đoạn nào đó mà hardware breakpoint cũng không bắt được.

Do `Paramater[3]` là con trỏ `Filename` (ban đầu chương trình dùng `strrchr` thay `\` thành `0x0` để cắt tên fiel thực thi, rồi `sprintf` để ghép với `\PolyjuicePotion.txt`)

<p align="center">

  <img src="img_assets/Pasted image 20261006082537.png">
</p>

<p align="center">

  <img src="img_assets/Pasted image 20261006090949.png">
</p>

<p align="center">

  <img src="img_assets/Pasted image 20261006092324.png">
</p>

<p align="center">

  <img src="img_assets/Pasted image 20261006092059.png">
</p>

Quay lại hàm `main`:

<p align="center">

  <img src="img_assets/Pasted image 20261006092615.png">
</p>

Resolve ra `NtSetInformationThread`, theo [tài liệu](https://anti-debug.checkpoint.com/techniques/interactive.html#ntsetinformationthread) thì nó là antidebug để giấu main thread khỏi debugger, f8 f9 thì chương trình sẽ tiếp tục chạy mà không va vào cái bp nào nữa. Đổi tham số `0x11` thành `0x0`, `rcx = -2` thì là `NtCurrentThread()` (`[[Pseudo Handle]]`).

<p align="center">

  <img src="img_assets/Pasted image 20261006093610.png">
</p>

Tiếp theo đọc chuỗi `AlbusDumbledore` ra buffer từ `FileName` rồi gán phần tử cuối là null terminator.

<p align="center">

  <img src="img_assets/Pasted image 20261006093827.png">
</p>

Ở đây tác giả obfus bằng cơ chế của window message (winproc) không gọi trực tiếp hàm mà thông qua window message

```cpp
v36[0] = Buffer; // Chứa "AlbusDumbledore \r\n" 
v36[1] = &sus; 
v36[2] = check_time; 
v36[3] = v20; 
v39[1] = sub_7FF7A3001B20; // Con trỏ hàm WndProc (Window Procedure)

``` 
Đăng kí `sub_7FF7A3001B20` bằng `RegisterClassExA`, `v36` thì truyền vào tham số cuối hàm `CreateWindowExA`

> The **CreateWindowEx** function sends WM_NCCREATE, WM_NCCALCSIZE, and WM_CREATE messages to the window being created. (https://winapi.freetechsecrets.com/win32/WIN32CreateWindowEx.htm)

Cái hay là mặc dù `sub_7FF7A3001B20` chỉ được gọi duy nhất 1 lần trong `main` nhưng cơ chế của `CreateWindowExA` thì lại gọi nó tới 3 lần lận:
- Lần 1 hdh ném vào `Msg = 129` `WM_NCCREATE`: Lấy tham số chứa chuỗi `"AlbusDumbledore"` (`v36[0]`) từ hàm `main` cất vào bộ nhớ ngầm của cửa sổ `SetWindowLongPtrW` xong return

<p align="center">

  <img src="img_assets/Pasted image 20261006111049.png">
</p>

- Lần 2 hdh ném vào `Msg = 131` `WM_NCCALCSIZE`: không phải 129 nên nhảy vào nhánh `else`. Lưu giá trị `131` vào `v37`, xong vì là `131 != 1` nên nó gọi `DefWindowProcW`

<p align="center">

  <img src="img_assets/Pasted image 20261006111234.png">
</p>

- Lần 3 thì hdh ném vào `Msg = 1` `WM_CREATE`: 

```c 
	      if ( WindowLongPtrW )
    {
      v11 = *(_DWORD *)(WindowLongPtrW + 32);
      *(_DWORD *)(WindowLongPtrW + 32) = Msg;
    }
    v12 = v11 ^ Msg;
    if ( Msg == 1 )
    {
      if ( WindowLongPtrW )
      {
        if ( *(_QWORD *)(WindowLongPtrW + 16) <= *(_QWORD *)(WindowLongPtrW + 24) )
        {
          v17 = *(_BYTE **)(WindowLongPtrW + 8);
          *v17 ^= 0x8Bu;
          v17[1] ^= 0x8Fu;
          v17[2] ^= 0x92u;
          v17[3] ^= 0x85u;
          v17[4] ^= 0x88u;
          v17[5] ^= 0x96u;
          v17[6] ^= 0x98u;
          v17[7] ^= 0x9Bu;
          v17[8] ^= 0x94u;
          v17[9] ^= 0x8Bu;
          v17[10] ^= 0x95u;
          v17[11] ^= 0xE6u;
          v17[12] ^= 0xEDu;
          v17[13] ^= 0xF0u;
          v17[14] ^= 0xE7u;
          SetEnvironmentVariableA("SESSION_TOKEN_CACHE", *(LPCSTR *)(WindowLongPtrW + 8));
        }
        else
        {
          v13 = *(_BYTE **)WindowLongPtrW;
          v14 = -1;
          do
            ++v14;
          while ( v13[v14] );
          if ( v14 )
          {
            v15 = 0;
            do
            {
              v13[v15++] ^= v12;
              v13 = *(_BYTE **)WindowLongPtrW;
              ++v10;
              v16 = -1;
              do
                ++v16;
              while ( v13[v16] );
            }
            while ( v10 < v16 );
          }
          *v13 ^= 0x8Bu;
          v13[1] ^= 0x8Fu;
          v13[2] ^= 0x92u;
          v13[3] ^= 0x85u;
          v13[4] ^= 0x88u;
          v13[5] ^= 0x96u;
          v13[6] ^= 0x98u;
          v13[7] ^= 0x9Bu;
          v13[8] ^= 0x94u;
          v13[9] ^= 0x8Bu;
          v13[10] ^= 0x95u;
          v13[11] ^= 0xE6u;
          v13[12] ^= 0xEDu;
          v13[13] ^= 0xF0u;
          v13[14] ^= 0xE7u;
        }
      }
      return -1;
    }

``` 

Lấy ra `v37` (`WindowLongPtrW + 32`) nãy được gán là `131` rồi xor với `Msg` là `1 = 130` (`0x82`)

`WindowLongPtrW + 16` là biến `checktime` (từ hàm `sub_7FF7A3001680` - đại khái hàm này dùng `GetProcessTimes` với `GetSystemTimeAsFileTime` để tính ra thời gian tiến trình hoạt động (checkdebug))
`WindowLongPtrW + 24` là `v20` được tính trong `main` (`0x2760`)

Đoạn này cần patch để đi vào nhánh `else` tại `v17` (`v36[1]`) trong `if` tính xong không sài trong `main`

<p align="center">

  <img src="img_assets/Pasted image 20261006162914.png">
</p>

Nhánh `else` thì có đụng vào chuỗi `AlbusDumbledore` hồi nãy, nó xor với key (`0x82`), rồi xor từng kí tự với các giá trị đã biết và kết quả ra được `HarryPotter` (đoạn này ban đầu mình không để ý và không patch nên hàm `main` gửi chuỗi `AlbusDumbledore` qua server mà vẫn không ra flag)

<p align="center">

  <img src="img_assets/Pasted image 20261006164543.png">
</p>

1 hint từ tác giả khi check kí tự đầu tiên `== A` thì in ra `[*] The Polyjuice Potion is still effective, preventing the true identity from being revealed.` nên chuỗi `HarryPotter` là chuẩn.

<p align="center">

  <img src="img_assets/Pasted image 20261006165235.png">
</p>

Tiếp theo tạo pipe `\\.\pipe\FlareChallenge`

<p align="center">

  <img src="img_assets/Pasted image 20261006165552.png">
</p>

`sub_7FF7A3001400` đọc resource `"BIN"` rồi tạo file `Partner_CTF.exe` trong thư mục `%TEMP%` `GetTempPathW`. Dùng `CreateProcessW` để tạo dump file ra temp đồng thời chạy luôn.

<p align="center">

  <img src="img_assets/Pasted image 20261006165950.png">
</p>

Cuối cùng là mở pipe, `WriteFile` để viết toàn bộ chuỗi `HarryPotter` vào pipe

<p align="center">

  <img src="img_assets/Pasted image 20261006170319.png">
</p>

Giờ debug file `Partner_CTF.exe` ngay sau khi nó kết nối được đến pipe nhờ hàm `CreateFileA()`. Ngay sau khi `GhostStream.exe` gọi `WriteFile` để ghi `HarryPotter` vào pipe thì bên server cũng gọi `ReadFile` để đọc chuỗi đó ra

<p align="center">

  <img src="img_assets/Pasted image 20261006172323.png">
</p>

```c
    *(_QWORD *)&v50 = 0x8B397AD735875C96uLL;
    *((_QWORD *)&v50 + 1) = 0xC85856BB286D0475uLL;
    *(_QWORD *)&v51 = 0x37A956A4E1DAEE35LL;
    *((_QWORD *)&v51 + 1) = 0xD340A27F9561581LL;
    memset(v65, 0, sizeof(v65));
    v63 = 640451310;
    *(_OWORD *)v61 = v50;
    v62 = v51;
    v64 = -1883;
    qword_140005678 = (unsigned __int64)strlen ^ 0xDEADBEEF;
    v8 = (unsigned __int64)strlen ^ 0xDEADBEEF;
    v9 = ::strlen(Buffer);
    if ( v9 > 0 )
    {
      si128 = _mm_load_si128((const __m128i *)&xmmword_140003420);
      v11 = &v55;
      v12 = (__m128)_mm_load_si128((const __m128i *)&xmmword_140003430);
      v13 = qword_140005678 + 270544960;
      v14 = 0;
      v15 = 8;
      do
      {
        v11 += 16;
        v16 = v15 + 4;
        v17 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(v15 - 8), 0), si128), v12);
        v18 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(v15 - 4), 0), si128), v12);
        v19 = _mm_packus_epi16(v17, v17);
        v20 = _mm_packus_epi16(v18, v18);
        *((_DWORD *)v11 - 5) = _mm_cvtsi128_si32(_mm_packus_epi16(v19, v19));
        *((_DWORD *)v11 - 4) = _mm_cvtsi128_si32(_mm_packus_epi16(v20, v20));
        v21 = _mm_cvtsi32_si128(v15);
        v15 += 16;
        v22 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(v21, 0), si128), v12);
        v23 = _mm_packus_epi16(v22, v22);
        v24 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(v16), 0), si128), v12);
        *((_DWORD *)v11 - 3) = _mm_cvtsi128_si32(_mm_packus_epi16(v23, v23));
        v25 = _mm_packus_epi16(v24, v24);
        *((_DWORD *)v11 - 2) = _mm_cvtsi128_si32(_mm_packus_epi16(v25, v25));
      }
      while ( (int)(v15 - 8) < 256 );
      v26 = v13 ^ 0xBADF00D;
      v27 = v54;
      for ( i = 0; i < 256; ++i )
      {
        v29 = *v27;
        v14 = (v29 + (unsigned __int8)Buffer[i % v9] + v14) % 256;
        v30 = &v54[v14];
        *v27++ = *v30;
        *v30 = v29;
      }

```

Đoạn này sài tập lệnh sse trông khá phức tạp cơ mà bên dưới là RC4 KSA, thực hiện hoán vị với key là `Buffer` (`"HarryPotter"`)

<p align="center">

  <img src="img_assets/Pasted image 20261006173456.png">
</p>

Đoạn này khá hiểm vì `v8` nãy được lấy từ `qword_140005678` (địa chỉ `strlen` xor `0xDEADBEEF` rồi `+ 270544960`)

<p align="center">

  <img src="img_assets/Pasted image 20261006173548.png">
</p>

Xong xor lại rồi trừ `270544960` rồi cấp quyền `PAGE_EXECUTE_READWRITE`

<p align="center">

  <img src="img_assets/Pasted image 20261006174456.png">
</p>

Ở dưới tiếp tục gọi `strlen` cho chuỗi `"Wingardium Leviosa"` (18)

<p align="center">

  <img src="img_assets/Pasted image 20261006174047.png">
</p>

F7 vào thì thấy code hàm `strlen` đã bị thay đổi, đó cũng là lí do gọi `VirtualProtect` để xin quyền `PAGE_EXECUTE_READWRITE` và mấy đoạn code ghi đè shellcode bên dưới.

<p align="center">

  <img src="img_assets/Pasted image 20261006174136.png">
</p>

Xor `eax` đưa `zf = 1` xong cộng `0x13` (19), `jnz` sẽ nhảy vì `ADD` thay đổi `zf = 0`, ở bên dưới tính toán xong không sài tại giá trị trả về luôn là `rax`....
Đoạn này mình debug ra 19 xong cũng không hiểu lắm, mất 1 lúc khá lâu không ra flag mới nhận ra là lệch length (độ dài chuỗi cần `strlen` `"Wingardium Leviosa"` = 18)

<p align="center">

  <img src="img_assets/Pasted image 20261006175202.png">
</p>

Ban đầu tưởng đoạn bơm shellcode vào dll này cũng chỉ cho vui tại mấy hàm trên gọi cho vui cơ mà để ra flag thì phải sửa lại đúng length = 18

<p align="center">

  <img src="img_assets/Pasted image 20261006175512.png">
</p>

Đoạn này thì khôi phục lại code hàm `strlen` rồi hủy quyền.

Thực hiện patch `v36` thành `0x12` (length 18)

<p align="center">

  <img src="img_assets/Pasted image 20261006185417.png">
</p>

<p align="center">

  <img src="img_assets/Pasted image 20261006185529.png">
</p>

Flag: `y0u_kn0w_n07h1n6_j0n_5n0w@flare-on.com`