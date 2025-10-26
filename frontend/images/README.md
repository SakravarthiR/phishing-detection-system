# Images Folder

This folder contains background images and other assets for the phishing detector frontend.

## Supported Image Formats
- PNG
- JPG/JPEG
- WebP
- SVG

## Background Images
Place your background images here and reference them in the CSS files:
- `login-styles.css` - For login page background
- `styles.css` - For main page background
- `scanner-styles.css` - For scanner page background

## Example Usage

### In CSS:
```css
body {
    background-image: url('images/your-background.jpg');
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}
```

## Recommended Image Sizes
- **Full Background**: 1920x1080px or larger
- **Icons**: 512x512px
- **Logos**: 256x256px

## Tips
- Use compressed/optimized images for faster loading
- Consider using WebP format for better compression
- Dark-themed backgrounds work best with the cyan/green color scheme
