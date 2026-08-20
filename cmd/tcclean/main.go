package main

import (
	"fmt"
	"os"

	"github.com/sagernet/netlink"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: tcclean <iface>")
		os.Exit(1)
	}
	link, err := netlink.LinkByName(os.Args[1])
	if err != nil {
		fmt.Println("link:", err)
		os.Exit(1)
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			fmt.Println("filter list:", err)
			continue
		}
		for _, f := range filters {
			if bf, ok := f.(*netlink.BpfFilter); ok {
				fmt.Printf("deleting bpf filter %s (parent=%x handle=%x)\n", bf.Name, parent, bf.Handle)
				if err := netlink.FilterDel(f); err != nil {
					fmt.Println("  del err:", err)
				}
			} else {
				fmt.Printf("keeping non-bpf filter type=%s\n", f.Type())
			}
		}
	}
	qdiscs, _ := netlink.QdiscList(link)
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			fmt.Println("deleting clsact qdisc")
			if err := netlink.QdiscDel(q); err != nil {
				fmt.Println("  qdisc del err:", err)
			}
		}
	}
	fmt.Println("done")
}
