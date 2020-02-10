#!/usr/local/bin/python3
import io
import os

import numpy as np
from PIL import Image, ImageDraw


def crop_horizontally(px, image):
    w, h = image.size
    left_area = (px / 2, 0, w, h)
    right_area = (0, 0, w - px, h)
    image = image.crop(left_area).crop(right_area)
    return image


def crop_vertically(px, image):
    w, h = image.size
    top_area = (0, px / 2, w, h)
    bottom_area = (0, 0, w, h - px)
    image = image.crop(top_area).crop(bottom_area)
    return image


def create_thumbnail(path):
    # Open the input image as numpy array, convert to RGB
    img = Image.open(path).convert("RGB")
    width, height = img.size
    size_min = min(width, height)
    if width > size_min:
        img = crop_horizontally(width - size_min, img)
    else:
        img = crop_vertically(height - size_min, img)
    width, height = img.size
    npImage = np.array(img)
    # Create same size alpha layer with circle
    alpha = Image.new('L', img.size, 0)
    draw = ImageDraw.Draw(alpha)
    draw.pieslice([0, 0, width, height], 0, 360, fill=255)

    # Convert alpha Image to numpy array
    npAlpha = np.array(alpha)

    # Add alpha layer to RGB
    npImage = np.dstack((npImage, npAlpha))

    # Save with alpha
    size = 180, 180
    img = Image.fromarray(npImage)
    img.thumbnail(size, Image.ANTIALIAS)

    img.save('.temp/temp.png', format='png')
    byteArr = io.BytesIO(open(".temp/temp.png", 'rb').read())
    os.remove('.temp/temp.png')
    return byteArr


if __name__ == '__main__':
    create_thumbnail()
