// Requires stb_image_write
// https://github.com/nothings/stb/blob/master/stb_image_write.h

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include <stdlib.h>
#include <stdint.h>

int main() {
	int width = 1920;
	int height = 1080;
	int channels = 4;
	
	uint8_t* data_begin = malloc(width * height * channels);
	uint8_t* data = data_begin;
	
	for (int y = 0; y < height; ++y) {
		for (int x = 0; x < width; ++x) {
			float xv = (float)x / (float)(width - 1);
			float yv = (float)y / (float)(height - 1);
			
			data[0] = (uint8_t)(xv * 255.f);
			data[1] = (uint8_t)(yv * 255.f);
			data[2] = 0;
			data[3] = 255;
			
			data += channels;
		}
	}
	
	stbi_write_png("output.png", width, height, channels, data_begin, width * channels);
	
	free(data_begin);
	
	return 0;
}