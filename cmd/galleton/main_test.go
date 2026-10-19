package main

import "testing"

func TestPauseFlags(t *testing.T) {
	var p pauseFlags
	for _, ok := range []string{"vinted=900", "wallapop=1", "vinted=86400"} {
		if err := p.Set(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	if got := p.String(); got != "vinted=900,wallapop=1,vinted=86400" {
		t.Fatalf("collected %q", got)
	}
	for _, bad := range []string{"vinted", "=900", "vinted=0", "vinted=86401", "vinted=x", "vinted=-5"} {
		if err := p.Set(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
