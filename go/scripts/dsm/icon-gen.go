//go:build ignore

package main

import (
	"flag"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"strconv"
)

type point struct {
	x, y float64
}

func main() {
	outDir := flag.String("out", "dist/dsm/icons", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		panic(err)
	}
	writeIcon(filepath.Join(*outDir, "PACKAGE_ICON.PNG"), 64)
	writeIcon(filepath.Join(*outDir, "PACKAGE_ICON_256.PNG"), 256)
	for _, size := range []int{16, 24, 32, 48, 64, 72, 256} {
		writeIcon(filepath.Join(*outDir, "dsmpass_"+strconv.Itoa(size)+".png"), size)
	}
}

func writeIcon(path string, size int) {
	scale := 4
	canvas := image.NewRGBA(image.Rect(0, 0, size*scale, size*scale))
	drawIcon(canvas, float64(size*scale))
	img := downsample(canvas, scale)

	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if err := png.Encode(file, img); err != nil {
		panic(err)
	}
}

func drawIcon(img *image.RGBA, s float64) {
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			img.SetRGBA(x, y, color.RGBA{0, 0, 0, 0})
		}
	}

	navy := color.RGBA{13, 27, 52, 255}
	blue := color.RGBA{35, 119, 255, 255}
	cyan := color.RGBA{41, 215, 214, 255}
	green := color.RGBA{81, 220, 151, 255}
	white := color.RGBA{248, 252, 255, 255}

	fillRoundedRect(img, 0.08*s, 0.08*s, 0.84*s, 0.84*s, 0.20*s, navy)
	fillCircle(img, 0.78*s, 0.20*s, 0.18*s, color.RGBA{28, 71, 132, 255})
	fillCircle(img, 0.17*s, 0.79*s, 0.14*s, color.RGBA{20, 96, 117, 255})

	strokeArc(img, 0.50*s, 0.53*s, 0.27*s, 0.31*s, 0.070*s, blue)
	stroke(img, 0.23*s, 0.55*s, 0.23*s, 0.70*s, 0.070*s, blue)
	stroke(img, 0.77*s, 0.55*s, 0.77*s, 0.70*s, 0.070*s, cyan)
	stroke(img, 0.25*s, 0.70*s, 0.75*s, 0.70*s, 0.085*s, cyan)

	fillRoundedRect(img, 0.36*s, 0.37*s, 0.28*s, 0.38*s, 0.055*s, color.RGBA{17, 43, 78, 255})
	fillCircle(img, 0.50*s, 0.49*s, 0.15*s, white)
	fillCircle(img, 0.50*s, 0.49*s, 0.075*s, navy)
	fillRoundedRect(img, 0.465*s, 0.55*s, 0.070*s, 0.16*s, 0.025*s, white)
	fillCircle(img, 0.50*s, 0.55*s, 0.035*s, white)

	stroke(img, 0.35*s, 0.36*s, 0.43*s, 0.28*s, 0.050*s, green)
	stroke(img, 0.43*s, 0.28*s, 0.62*s, 0.28*s, 0.050*s, green)
}

func fillRoundedRect(img *image.RGBA, x, y, w, h, r float64, c color.RGBA) {
	for py := int(y); py < int(y+h); py++ {
		for px := int(x); px < int(x+w); px++ {
			cx := math.Max(x+r, math.Min(float64(px), x+w-r))
			cy := math.Max(y+r, math.Min(float64(py), y+h-r))
			if math.Hypot(float64(px)-cx, float64(py)-cy) <= r {
				img.SetRGBA(px, py, c)
			}
		}
	}
}

func fillCircle(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	r2 := r * r
	for y := int(cy - r); y <= int(cy+r); y++ {
		for x := int(cx - r); x <= int(cx+r); x++ {
			if math.Pow(float64(x)-cx, 2)+math.Pow(float64(y)-cy, 2) <= r2 {
				img.SetRGBA(x, y, c)
			}
		}
	}
}

func fillPoly(img *image.RGBA, pts []point, c color.RGBA) {
	minX, minY := pts[0].x, pts[0].y
	maxX, maxY := minX, minY
	for _, p := range pts[1:] {
		minX = math.Min(minX, p.x)
		minY = math.Min(minY, p.y)
		maxX = math.Max(maxX, p.x)
		maxY = math.Max(maxY, p.y)
	}
	for y := int(minY); y <= int(maxY); y++ {
		for x := int(minX); x <= int(maxX); x++ {
			if insidePoly(float64(x)+0.5, float64(y)+0.5, pts) {
				img.SetRGBA(x, y, c)
			}
		}
	}
}

func insidePoly(x, y float64, pts []point) bool {
	inside := false
	j := len(pts) - 1
	for i := range pts {
		if (pts[i].y > y) != (pts[j].y > y) &&
			x < (pts[j].x-pts[i].x)*(y-pts[i].y)/(pts[j].y-pts[i].y)+pts[i].x {
			inside = !inside
		}
		j = i
	}
	return inside
}

func stroke(img *image.RGBA, x1, y1, x2, y2, width float64, c color.RGBA) {
	minX := int(math.Min(x1, x2) - width)
	maxX := int(math.Max(x1, x2) + width)
	minY := int(math.Min(y1, y2) - width)
	maxY := int(math.Max(y1, y2) + width)
	half := width / 2
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if distanceToSegment(float64(x), float64(y), x1, y1, x2, y2) <= half {
				img.SetRGBA(x, y, c)
			}
		}
	}
}

func strokeArc(img *image.RGBA, cx, cy, rx, ry, width float64, c color.RGBA) {
	steps := 48
	prevX := cx - rx
	prevY := cy
	for i := 1; i <= steps; i++ {
		t := math.Pi - (math.Pi * float64(i) / float64(steps))
		x := cx + math.Cos(t)*rx
		y := cy - math.Sin(t)*ry
		stroke(img, prevX, prevY, x, y, width, c)
		prevX, prevY = x, y
	}
}

func distanceToSegment(px, py, x1, y1, x2, y2 float64) float64 {
	dx, dy := x2-x1, y2-y1
	if dx == 0 && dy == 0 {
		return math.Hypot(px-x1, py-y1)
	}
	t := ((px-x1)*dx + (py-y1)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(x1+t*dx), py-(y1+t*dy))
}

func downsample(src *image.RGBA, scale int) *image.RGBA {
	w := src.Bounds().Dx() / scale
	h := src.Bounds().Dy() / scale
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var r, g, b, a int
			for sy := 0; sy < scale; sy++ {
				for sx := 0; sx < scale; sx++ {
					c := src.RGBAAt(x*scale+sx, y*scale+sy)
					r += int(c.R)
					g += int(c.G)
					b += int(c.B)
					a += int(c.A)
				}
			}
			n := scale * scale
			dst.SetRGBA(x, y, color.RGBA{uint8(r / n), uint8(g / n), uint8(b / n), uint8(a / n)})
		}
	}
	return dst
}

func mix(a, b color.RGBA, t float64) color.RGBA {
	return color.RGBA{
		R: uint8(float64(a.R)*(1-t) + float64(b.R)*t),
		G: uint8(float64(a.G)*(1-t) + float64(b.G)*t),
		B: uint8(float64(a.B)*(1-t) + float64(b.B)*t),
		A: 255,
	}
}
