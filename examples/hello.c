#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(int argc, const char* argv[]) {
	for (int i = 0; i < argc; ++i) {
		printf("%d: %s\n", i, argv[i]);
	}
	
	printf("\n");
	
	for (int i = 0; i < 10; ++i) {
		time_t unix_time;

		time (&unix_time);
		struct tm* time_info = localtime(&unix_time);
		
		printf("Current time and date: %s", asctime(time_info));
		printf("Timezone is probably wrong though.\n");
		
		usleep(500 * 1000);
	}
	
	return 0;
}