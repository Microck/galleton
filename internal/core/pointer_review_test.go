package core

import "testing"

func TestPointerRejectsSignedArrayIndex(t *testing.T) {
	doc, err := parseJSON([]byte(`{"items":["zero","one"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []string{"+1", "-0", "01", "1.0", " 1", "\u0661"} {
		if _, ok := pointer(doc, "/items/"+index); ok {
			t.Errorf("invalid array index %q was accepted", index)
		}
	}
	for _, index := range []string{"0", "1"} {
		if _, ok := pointer(doc, "/items/"+index); !ok {
			t.Errorf("valid array index %q was rejected", index)
		}
	}
	object := map[string]any{"+1": "valid object key", "-0": "also valid"}
	for key := range object {
		if _, ok := pointer(object, "/"+key); !ok {
			t.Errorf("object key %q was treated as an array index", key)
		}
	}
}
