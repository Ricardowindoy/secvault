// gfbench：无业务纯 GF(256)/纠删码基准（参考资料坑位清单逐项验证）。
// 运行：taskset -c 6,7 ./gfbench [-quick]（大核）；taskset -c 0 ./gfbench -quick（小核对照）。
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/reedsolomon"
)

// ---------- 频率/温度监控（坑 #25：降频检测） ----------

type freqMon struct {
	paths    []string
	labels   []string
	tempPath string
	min      map[string]int64
	max      map[string]int64
	sum      map[string]int64
	n        map[string]int64
	maxTemp  float64
	stop     chan struct{}
	done     chan struct{}
}

func startFreqMon() *freqMon {
	m := freqMin()
	return m
}

func freqMin() *freqMon {
	m := &freqMon{
		paths: []string{
			"/sys/devices/system/cpu/cpu6/cpufreq/scaling_cur_freq",
			"/sys/devices/system/cpu/cpu7/cpufreq/scaling_cur_freq",
			"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
		},
		labels: []string{"cpu6大", "cpu7大", "cpu0小"},
		min:    map[string]int64{}, max: map[string]int64{}, sum: map[string]int64{}, n: map[string]int64{},
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	// 找大核热区
	if ents, err := os.ReadDir("/sys/class/thermal"); err == nil {
		for _, e := range ents {
			if !strings.HasPrefix(e.Name(), "thermal_zone") {
				continue
			}
			typ, err1 := os.ReadFile("/sys/class/thermal/" + e.Name() + "/type")
			if err1 == nil && strings.TrimSpace(string(typ)) == "cpub_thermal_zone" {
				m.tempPath = "/sys/class/thermal/" + e.Name() + "/temp"
				break
			}
		}
	}
	go func() {
		defer close(m.done)
		tk := time.NewTicker(100 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-tk.C:
				for i, p := range m.paths {
					if b, err := os.ReadFile(p); err == nil {
						v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
						l := m.labels[i]
						if _, ok := m.min[l]; !ok || v < m.min[l] {
							m.min[l] = v
						}
						if v > m.max[l] {
							m.max[l] = v
						}
						m.sum[l] += v
						m.n[l]++
					}
				}
				if m.tempPath != "" {
					if b, err := os.ReadFile(m.tempPath); err == nil {
						if v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
							if v/1000 > m.maxTemp {
								m.maxTemp = v / 1000
							}
						}
					}
				}
			}
		}
	}()
	return m
}

func (m *freqMon) report() {
	for _, l := range m.labels {
		if m.n[l] == 0 {
			continue
		}
		avg := m.sum[l] / m.n[l]
		fmt.Printf("  %-8s 频率 min/avg/max = %d/%d/%d MHz\n", l, m.min[l]/1000, avg/1000, m.max[l]/1000)
	}
	if m.maxTemp > 0 {
		fmt.Printf("  大核最高温度 %.1f°C\n", m.maxTemp)
	}
}

// ---------- preflight ----------

func preflight() {
	fmt.Printf("== 预检 ==\n")
	fmt.Printf("后端: %s | GOMAXPROCS=%d\n", backendName, runtime.GOMAXPROCS(0))
	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu6/cpufreq/scaling_governor"); err == nil {
		fmt.Printf("governor(cpu6): %s（坑#26：ondemand 升频慢）", strings.TrimSpace(string(b)))
		if b2, err := os.ReadFile("/sys/devices/system/cpu/cpu6/cpufreq/cpuinfo_max_freq"); err == nil {
			fmt.Printf(" max=%dMHz", toI64(b2)/1000)
		}
		fmt.Println()
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		line := strings.SplitN(string(b), "\n", 2)[0]
		fmt.Printf("内存: %s\n", strings.TrimSpace(line))
	}
	n := 0
	if ents, err := os.ReadDir("/sys/devices/system/cpu/vulnerabilities"); err == nil {
		for _, e := range ents {
			if b, err := os.ReadFile("/sys/devices/system/cpu/vulnerabilities/" + e.Name()); err == nil {
				if strings.Contains(string(b), "Mitigation") {
					n++
				}
			}
		}
	}
	fmt.Printf("内核缓解措施(Mitigation)项数: %d（坑#28）\n", n)
	fmt.Printf("BSP 内核未暴露 per-cpu cache sysfs（坑#21 依赖大小扫描验证；A76 L2=512KB/核）\n")
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Cpus_allowed_list") {
				fmt.Printf("本进程 CPU 亲和: %s\n", strings.TrimSpace(strings.SplitN(line, "\t", 2)[1]))
			}
		}
	}
	fmt.Println()
}

func toI64(b []byte) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// ---------- 基准框架 ----------

func autoBench(name string, bytesPerRep, gfBytesPerRep float64, fn func(reps int) time.Duration) {
	fn(1) // 暖机（含首次表构建/页分配）
	reps := 1
	var sum time.Duration
	best := time.Hour
	measured := 0
	for {
		d := fn(reps)
		per := d / time.Duration(reps)
		if per < best {
			best = per
		}
		sum += d
		measured += reps
		if sum >= 800*time.Millisecond || measured >= 1<<20 {
			break
		}
		reps *= 2
	}
	avg := sum / time.Duration(measured)
	bestMB := bytesPerRep / 1e6 / best.Seconds()
	avgMB := bytesPerRep / 1e6 / avg.Seconds()
	gf := "     -"
	if gfBytesPerRep > 0 {
		gf = fmt.Sprintf("%8.1f", gfBytesPerRep/1e9/best.Seconds())
	}
	fmt.Printf("%-40s %10.1f %12.1f %10s\n", name, bestMB, avgMB, gf)
}

func fill(s []byte, seed byte) {
	for i := range s {
		s[i] = byte(i*31) ^ seed
	}
}

// ---------- GF 基础（Go 侧矩阵） ----------

func gfMul(a, b byte) byte {
	var acc byte
	for b != 0 {
		if b&1 != 0 {
			acc ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1D
		}
		b >>= 1
	}
	return acc
}

func gfPow(a byte, n int) byte {
	r := byte(1)
	for n > 0 {
		if n&1 != 0 {
			r = gfMul(r, a)
		}
		a = gfMul(a, a)
		n >>= 1
	}
	return r
}

// cauchyMatrix 生成 m×k Cauchy 矩阵（任意 k×k 子矩阵可逆）
func cauchyMatrix(k, m int) [][]byte {
	out := make([][]byte, m)
	for p := 0; p < m; p++ {
		row := make([]byte, k)
		xp := byte(k + p)
		for i := 0; i < k; i++ {
			row[i] = gfPow(xp^byte(i), 254) // gf_inv
		}
		out[p] = row
	}
	return out
}

// ---------- 各基准 ----------

func benchMemcpy() {
	const N = 64 << 20
	src := make([]byte, N)
	dst := make([]byte, N)
	fill(src, 1)
	autoBench("memcpy(Go copy) 64MB 上限参考", N, 0, func(reps int) time.Duration {
		t0 := time.Now()
		for i := 0; i < reps; i++ {
			copy(dst, src)
		}
		return time.Since(t0)
	})
}

func benchXorC() {
	const N = 64 << 20
	src := make([]byte, N)
	dst := make([]byte, N)
	fill(src, 2)
	fill(dst, 3)
	autoBench("XOR 内核(C NEON) 64MB", N, 0, func(reps int) time.Duration {
		t0 := time.Now()
		for i := 0; i < reps; i++ {
			xorC(dst, src)
		}
		return time.Since(t0)
	})
}

func benchMulAddSweep() {
	fmt.Println("-- muladd X 随工作集变化（坑#21 L2=512KB 验证）--")
	for _, sz := range []int{32 << 10, 128 << 10, 512 << 10, 2 << 20, 16 << 20} {
		src := make([]byte, sz)
		dst := make([]byte, sz)
		fill(src, 4)
		fill(dst, 5)
		tab := buildNibbleTable(0x53)
		name := fmt.Sprintf("muladd X 工作集 %s", humanBytes(sz))
		autoBench(name, float64(sz), 0, func(reps int) time.Duration {
			t0 := time.Now()
			for i := 0; i < reps; i++ {
				mulAddC(dst, src, tab, 0x53)
			}
			return time.Since(t0)
		})
	}
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func benchKlauspostX() {
	const k, m, size = 64, 1, 1 << 20
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		panic(err)
	}
	shards := make([][]byte, k+m)
	for i := range shards {
		shards[i] = make([]byte, size)
		if i < k {
			fill(shards[i], 6)
		}
	}
	autoBench("klauspost X 测量 New(64,1) 1MB shard", float64(k*size), 0, func(reps int) time.Duration {
		t0 := time.Now()
		for i := 0; i < reps; i++ {
			if err := enc.Encode(shards); err != nil {
				panic(err)
			}
		}
		return time.Since(t0)
	})
}

func benchKlauspostConfig(k, m, size int) {
	name := fmt.Sprintf("klauspost classic/leopard (%d,%d) shard %s", k, m, humanBytes(size))
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		panic(err)
	}
	shards := make([][]byte, k+m)
	for i := range shards {
		shards[i] = make([]byte, size)
		if i < k {
			fill(shards[i], 7)
		}
	}
	autoBench(name, float64(k*size), float64(m*k*size), func(reps int) time.Duration {
		t0 := time.Now()
		for i := 0; i < reps; i++ {
			if err := enc.Encode(shards); err != nil {
				panic(err)
			}
		}
		return time.Since(t0)
	})
}

func benchCGO(k, m, size int) {
	name := fmt.Sprintf("cgo NEON vtbl RS(%d,%d) shard %s", k, m, humanBytes(size))
	shards := make([][]byte, k+m)
	for i := range shards {
		shards[i] = make([]byte, size)
		if i < k {
			fill(shards[i], 8)
		}
	}
	mat := cauchyMatrix(k, m)
	tabCache := map[byte][]byte{}
	getTab := func(c byte) []byte {
		if t, ok := tabCache[c]; ok {
			return t
		}
		t := buildNibbleTable(c)
		tabCache[c] = t
		return t
	}
	autoBench(name, float64(k*size), float64(m*k*size), func(reps int) time.Duration {
		t0 := time.Now()
		for r := 0; r < reps; r++ {
			for i := k; i < k+m; i++ {
				clear(shards[i])
			}
			for p := 0; p < m; p++ {
				for i := 0; i < k; i++ {
					c := mat[p][i]
					if c == 1 {
						xorC(shards[k+p], shards[i])
					} else {
						mulAddC(shards[k+p], shards[i], getTab(c), c)
					}
				}
			}
		}
		return time.Since(t0)
	})
}

// ---------- main ----------

func main() {
	quick := flag.Bool("quick", false, "只跑核心项（大小核对比）")
	flag.Parse()
	preflight()
	mon := startFreqMon()
	fmt.Println("== 基准 ==（最佳/平均为单次操作的吞吐；GF乘加列=每秒处理的 GF 乘加字节数）")
	fmt.Printf("%-42s %10s %12s %10s\n", "名称", "最佳MB/s", "平均MB/s", "GF GB/s")

	benchMemcpy()
	benchXorC()
	benchMulAddSweep()
	benchKlauspostX()

	if !*quick {
		benchKlauspostConfig(16, 4, 1<<20)
		benchKlauspostConfig(64, 16, 256<<10)
	}
	benchKlauspostConfig(128, 64, 256<<10)
	benchKlauspostConfig(256, 128, 4<<10)
	if !*quick {
		benchKlauspostConfig(256, 128, 256<<10)
	}
	benchCGO(16, 4, 1<<20)
	if !*quick {
		benchCGO(128, 64, 256<<10)
	}

	close(mon.stop)
	<-mon.done
	fmt.Println("== 频率/温度（坑#25/#26 验证）==")
	mon.report()
}
