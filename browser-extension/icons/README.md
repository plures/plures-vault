# Browser Extension Icons

The extension icons need to be generated from `icon.svg`:

```bash
# Using ImageMagick:
convert icon.svg -resize 16x16 icon-16.png
convert icon.svg -resize 48x48 icon-48.png
convert icon.svg -resize 128x128 icon-128.png

# Or using rsvg-convert:
rsvg-convert icon.svg -w 16 -h 16 -o icon-16.png
rsvg-convert icon.svg -w 48 -h 48 -o icon-48.png
rsvg-convert icon.svg -w 128 -h 128 -o icon-128.png
```

For development/testing, Chrome will use a default icon if PNGs are missing.
