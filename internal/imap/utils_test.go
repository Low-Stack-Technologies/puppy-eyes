package imap

import "testing"

func TestParseSequenceSet(t *testing.T) {
	set := parseSequenceSet("1,3:4,*", 5)
	for _, v := range []int{1, 3, 4, 5} {
		if !set[v] {
			t.Fatalf("expected sequence %d to be included", v)
		}
	}
	if set[2] {
		t.Fatalf("did not expect sequence 2 to be included")
	}
}

func TestNormalizeFlags(t *testing.T) {
	flags := normalizeFlags([]string{"\\seen", "\\Seen", "Custom", "custom", "\\Deleted"})
	want := map[string]bool{"\\Seen": true, "\\Deleted": true, "Custom": true, "custom": true}
	for _, f := range flags {
		if !want[f] {
			t.Fatalf("unexpected flag %s in output", f)
		}
		delete(want, f)
	}
	if len(want) != 0 {
		t.Fatalf("missing flags after normalization: %v", want)
	}
}
