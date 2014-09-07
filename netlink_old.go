package main

import . "syscall"
import "fmt"
import "unsafe"

type NetlinkAuditRequest struct {
    Header NlMsghdr
    Data   RtGenmsg
}

func (rr *NetlinkAuditRequest) toWireFormat() []byte {
    b := make([]byte, rr.Header.Len)
    *(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
    *(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
    *(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
    *(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
    *(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
    b[16] = byte(rr.Data.Family)
    return b
}

func newNetlinkAuditRequest(proto, seq, family int) []byte {
    rr := &NetlinkAuditRequest{}
    rr.Header.Len = uint32(NLMSG_HDRLEN + SizeofRtGenmsg)
    rr.Header.Type = uint16(proto)
    rr.Header.Flags = NLM_F_REQUEST//MSG_PEEK|MSG_DONTWAIT//NLM_F_REQUEST //| NLM_F_ACK
    rr.Header.Seq = uint32(seq)
    rr.Data.Family = uint8(family)
    return rr.toWireFormat()
}

func nlmAlignOf(msglen int) int {
    return (msglen + NLMSG_ALIGNTO - 1) & ^(NLMSG_ALIGNTO - 1)
}

func main() {

    // Create a netlink socket
    s, err := Socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT)
    if err != nil {
        fmt.Println("scoket error:")
        fmt.Println(err)
        return
    }
    defer Close(s)

    lsa := &SockaddrNetlink{Family: AF_NETLINK}
    if err := Bind(s, lsa); err != nil {
        fmt.Println("bind error:")
        fmt.Println(err)
        return
    }
    fmt.Println("**** Starting Netlink")

    // sendto(fd, &req, req.nlh.nlmsg_len, 0,(struct sockaddr*)&addr, sizeof(addr))
    // sendto(3, "\20\0\0\0\350\3\5\0\1\0\0\0\0\0\0\0", 16, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 16
    // sendto(3, "\21\0\0\0\350\3\5\0\1\0\0\0\0\0\0\0\t", 17, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 17
    wb := newNetlinkAuditRequest(1000, 1, NETLINK_AUDIT)
    if err := Sendto(s, wb, 0, lsa); err != nil {
        fmt.Println("sending error: ", err)
        return
    }
    var tab []byte
done:
    for {

        // recvfrom(fd, &rep->msg, sizeof(rep->msg), block|peek,   (struct sockaddr*)&nladdr, &nladdrlen);
        // recvfrom(3, "$\0\0\0\2\0\0\0\1\0\0\0\234K\0\0\0\0\0\0\20\0\0\0\350\3\5\0\1\0\0\0"..., 8988, MSG_PEEK|MSG_DONTWAIT, {sa_family=AF_NETLINK, pid=0, groups=00000000}, [12]) = 36
        // recvfrom(3, "$\0\0\0\2\0\0\0\1\0\0\0Pm\0\0\0\0\0\0\21\0\0\0\350\3\5\0\1\0\0\0"..., 4096, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, [12]) = 36
        rb := make([]byte, Getpagesize())
        nr, _, err := Recvfrom(s, rb, MSG_PEEK|MSG_DONTWAIT)
        //nr, _, err := Recvfrom(s, rb, 0)
        if err != nil {
            fmt.Println("rec err: ", err)
            return
        }
        if nr < NLMSG_HDRLEN {
            fmt.Println(EINVAL)
            fmt.Println("nr < nlmsg hdrlen")
            return
        }
        rb = rb[:nr]
        tab = append(tab, rb...)
        msgs, err := ParseNetlinkMessage(rb)

        if err != nil {
            fmt.Println("parse error:", err)
            return
        }

        for _, m := range msgs {
 
            lsa, err := Getsockname(s)
            if err != nil {
                fmt.Println("get socket name error:", err)
                return
            }

            switch v := lsa.(type) {
            case *SockaddrNetlink:
                if m.Header.Seq != 1 || m.Header.Pid != v.Pid {
                    fmt.Println("case")
                    fmt.Println(EINVAL)
                    return 
                }
            default:
                fmt.Println(EINVAL)
                fmt.Println("default case")
                return
            }
            if m.Header.Type == NLMSG_DONE {
                break done
            }

            if m.Header.Type == NLMSG_ERROR {
                fmt.Println(EINVAL)
                fmt.Println("somewhere below")
                return
            }

        }
        fmt.Println(string(tab[:]));
    }
}
