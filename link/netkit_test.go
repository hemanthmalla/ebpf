package link

import (
	"fmt"
	"net"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestAttachNetkit(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.7", "Netkit Device")

	prog := mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachNetkitPrimary, "")
	link, _ := mustAttachNetkit(t, prog, ebpf.AttachNetkitPrimary)

	testLink(t, link, prog)
}

func TestNetkitAnchor(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.7", "Netkit Device")

	a := mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachNetkitPrimary, "")
	b := mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachNetkitPrimary, "")

	linkA, iface := mustAttachNetkit(t, a, ebpf.AttachNetkitPrimary)

	programInfo, err := a.Info()
	qt.Assert(t, qt.IsNil(err))
	programID, _ := programInfo.ID()

	linkInfo, err := linkA.Info()
	qt.Assert(t, qt.IsNil(err))
	linkID := linkInfo.ID

	for _, anchor := range []Anchor{
		Head(),
		Tail(),
		BeforeProgram(a),
		BeforeProgramByID(programID),
		AfterLink(linkA),
		AfterLinkByID(linkID),
	} {
		t.Run(fmt.Sprintf("%T", anchor), func(t *testing.T) {
			linkB, err := AttachNetkit(NetkitOptions{
				Program:   b,
				Attach:    ebpf.AttachNetkitPrimary,
				Interface: iface,
				Anchor:    anchor,
			})
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.IsNil(linkB.Close()))
		})
	}
}

func mustAttachNetkit(tb testing.TB, prog *ebpf.Program, attachType ebpf.AttachType) (Link, int) {
	// TODO(hemanthmalla): Update device name based on CI setup
	iface, err := net.InterfaceByName("nk1")
	qt.Assert(tb, qt.IsNil(err))

	link, err := AttachNetkit(NetkitOptions{
		Program:   prog,
		Attach:    attachType,
		Interface: iface.Index,
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() { qt.Assert(tb, qt.IsNil(link.Close())) })

	return link, iface.Index
}
