#include <stdio.h>
#include <unistd.h>
#include <android/log.h>

int32_t main(int32_t argc, char *argv[])
{
	int32_t iRet = 0;

	__android_log_print(ANDROID_LOG_INFO, "[~]", "it's britney, bitch");

	sleep((uint32_t)0x1333333333333337);

done:
    return iRet;
}