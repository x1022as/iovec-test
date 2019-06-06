package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
	//"github.com/x1022as/test"

	"golang.org/x/sys/unix"
)

type payload struct {
	a int32
	b int32
}

type msg struct {
	size int32
	pl   payload
}

const (
	INT64_SIZE   = int(unsafe.Sizeof(int64(0)))
	CMSGHDR_SIZE = int(unsafe.Sizeof(syscall.Cmsghdr{}))
	MSGHDR_SIZE  = int(unsafe.Sizeof(syscall.Msghdr{}))
	INT_SIZE     = int(unsafe.Sizeof(int(0)))
	INT32_SIZE   = int(unsafe.Sizeof(int32(0)))
)

func cmsg_align(l int) int {
	return (l + INT64_SIZE - 1) & (^(INT64_SIZE - 1))
}

func cmsg_space(l int) int {
	return CMSGHDR_SIZE + cmsg_align(l)
}

func cmsg_len(l int) uint64 {
	return uint64(CMSGHDR_SIZE + l)
}

func main() {
	var fds []int
	//var fdnum int

	addr, err := net.ResolveUnixAddr("unix", "./tmp.sock")
	if err != nil {
		fmt.Println("resolve unix address failed\n")
		return
	}

	c, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		fmt.Println("dial unix failed\n")
		return
	}

	mbuf := make([]byte, 12)
	mm := (*msg)(unsafe.Pointer(&mbuf[0]))
	mm.size = 8
	mm.pl.a = 5
	mm.pl.b = 10
	fmt.Printf("msg len is %d\nmsg is %v\n", len(mbuf), mbuf)

	// f1, _ := os.OpenFile("hello", os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(0644))
	// f1.Write([]byte("hello\n"))
	data1, f1, err := initShm("tmp", 10, 0)
	if err != nil {
		fmt.Printf("init shm failed: %s\n", err)
		return
	}
	fds = append(fds, f1)
	copy(data1[:5], []byte("hello"))
	defer endShm("tmp", 0, data1)

	data2, f2, err := initShm("tmp", 10, 1)
	if err != nil {
		fmt.Printf("init shm failed: %s\n", err)
		return
	}
	fds = append(fds, f2)
	copy(data2[:5], []byte("world"))
	defer endShm("tmp", 1, data2)
	/*
		f2, _ := os.OpenFile("world", os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(0644))
		f2.Write([]byte("world\n"))
		fds = append(fds, int(f2.Fd()))
		defer f2.Close()
	*/
	// fdnum = 2

	/*
		buf := make([]byte, cmsg_space(fdnum*INT32_SIZE))
		cmsg := (*syscall.Cmsghdr)(unsafe.Pointer(&buf))
		cmsg.Level = syscall.SOL_SOCKET
		cmsg.Type = syscall.SCM_RIGHTS
		cmsg.Len = cmsg_len(fdnum * INT32_SIZE)
		cmsg_data := uintptr(unsafe.Pointer(cmsg)) + uintptr(CMSGHDR_SIZE)
		test.Memcpy(unsafe.Pointer(cmsg_data), unsafe.Pointer(&fds), uintptr(fdnum*INT32_SIZE))
	*/
	rights := syscall.UnixRights(fds...)
	fmt.Printf("rights is %v\n", rights)
	fmt.Printf("cmsg len is %d\n", len(rights))

	cf, err := c.File()
	if err != nil {
		fmt.Printf("failed to get file from unix conn: %s\n", err)
		return
	}

	// user msghdr instead of msgbuf directly
	/*
		b := make([]byte, MSGHDR_SIZE)
		mh := (*syscall.Msghdr)(unsafe.Pointer(&b[0]))
		iov := syscall.Iovec{}
		iov.Base = (*byte)(unsafe.Pointer(&mbuf[0]))
		iov.SetLen(12)
		mh.Iov = &iov
		mh.Iovlen = 1
	*/

	//n, err := syscall.SendmsgN(int(cf.Fd()), mbuf, rights, nil, 0)
	n, err := syscall.SendmsgN(int(cf.Fd()), mbuf, rights, nil, 0)
	if err != nil {
		fmt.Printf("sendmsg failed with %s\n", err)
		return
	}
	fmt.Printf("sendmsg done, with num of %d\n", n)

	/*
		n, oobn, err := c.WriteMsgUnix(mbuf, rights, addr)
		if err != nil {
			fmt.Printf("write message unix failed with %s\n", err)
			return
		}
		fmt.Printf("n is %d, oobn is %d\n", n, oobn)
	*/
	time.Sleep(10 * time.Second)
}

func shmOpen(regionName string, flags int, perm os.FileMode) (*os.File, error) {
	devShm := "/dev/shm/"
	fd, err := unix.Open(devShm+regionName, flags|unix.O_CLOEXEC, uint32(perm))
	if err != nil {
		fmt.Printf("open shm file %s failed: %s\n", regionName, err)
		return nil, err
	}

	return os.NewFile(uintptr(fd), regionName), nil
}

func shmUnlink(regionName string) error {
	devShm := "/dev/shm/"
	return unix.Unlink(devShm + regionName)
}

func initShm(path string, size int, idx int) ([]byte, int, error) {
	pathIdx := fmt.Sprintf("%s%d", path, idx)
	sf, err := shmOpen(pathIdx, syscall.O_RDWR|syscall.O_CREAT, 0666)
	if err != nil {
		fmt.Printf("shm open failed %s\n", err)
		return nil, -1, err
	}
	if err := syscall.Ftruncate(int(sf.Fd()), int64(size)); err != nil {
		fmt.Printf("shm file truncate failed: %s\n", err)
		return nil, -1, err
	}
	data, err := syscall.Mmap(int(sf.Fd()), 0, size, syscall.PROT_READ|
		syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		fmt.Printf("shm mmap failed %s\n", err)
		return nil, -1, err
	}
	return data, int(sf.Fd()), nil
}

func endShm(path string, idx int, data []byte) error {
	pathIdx := fmt.Sprintf("%s%d", path, idx)
	if err := syscall.Munmap(data); err != nil {
		fmt.Printf("munmap failed: %s\n", err)
		return err
	}
	if err := shmUnlink(pathIdx); err != nil {
		fmt.Printf("shm unlink failed:%s\n", err)
		return err
	}
	return nil
}

/*
void* init_shm(const char* path, size_t size, int idx)
{
    int fd = 0;
    void* result = 0;
    char path_idx[PATH_MAX];
    int oflags = 0;

    sprintf(path_idx, "%s%d", path, idx);

    oflags = O_RDWR | O_CREAT;

    fd = shm_open(path_idx, oflags, 0666);
    if (fd == -1) {
        perror("shm_open");
        goto err;
    }

    if (ftruncate(fd, size) != 0) {
        perror("ftruncate");
        goto err;
    }

    result = init_shm_from_fd(fd, size);
    if (!result) {
        goto err;
    }

    shm_fds[idx] = fd;

    return result;

err:
    close(fd);
    return 0;
}
*/
