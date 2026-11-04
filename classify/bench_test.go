package classify_test

import (
	"context"
	"testing"

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/internal/testkit"
)

func benchAPK() []byte {
	return testkit.Zip(
		testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("com.bench", false, "android.permission.INTERNET")},
		testkit.File{Name: "classes.dex", Data: dex()},
		testkit.File{Name: "assets/data.json", Data: []byte(`{"k": [1, 2, 3]}`)},
		testkit.File{Name: "lib/libx.so", Data: testkit.ELF(4096)},
	)
}

// Warm: the whole-result cache (memory LRU) answers.
func BenchmarkClassifyAPKWarm(b *testing.B) {
	e := open(b)
	src := classify.Bytes(benchAPK())
	e.Classify(context.Background(), src)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Classify(context.Background(), src)
	}
}

// Cold: a fresh workdir each time, so every classifier runs.
func BenchmarkClassifyAPKCold(b *testing.B) {
	data := benchAPK()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		e := open(b)
		b.StartTimer()
		e.Classify(context.Background(), classify.Bytes(data))
	}
}

func BenchmarkClassifyQuick(b *testing.B) {
	e := open(b)
	data := benchAPK()
	for i := 0; i < b.N; i++ {
		// A distinct suffix defeats the result cache.
		e.Classify(context.Background(), classify.Bytes(append(data, byte(i), byte(i>>8))), classify.WithDepth(classify.Quick))
	}
}
