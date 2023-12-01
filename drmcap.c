#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <setjmp.h>
#include <xf86drm.h>
#include <xf86drmMode.h>
#include <errno.h>
#include <string.h>
#include <drm_fourcc.h>
#include <stdbool.h>

typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned long int uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#define VERSION "1.4"

// Does DRM support VBlank?
//#define SUPPORT_VBLANK

#define DEF_DRM_PATH    "/dev/dri/card0"
char sDrm_name[256];

#define DEF_OUTPUT_FOLDER   "."
char sOutput_folder[256];

#define FLAG_SAVE_RAW   0x01
#define FLAG_TILE       0x02
#define FLAG_PRINT_ONLY 0x04
#define FLAG_REPEAT     0x08
unsigned int iFlag = 0;

// Specific plane to capture
#define MAX_PLANE 64
int iTargetPlane = -1;

// Repeat mode:
#define DEF_REPEAT_COUNT    30
#define DEF_REPEAT_INTERVAL 15  /* in ms */
int iRepeatCount = 0;
int iRepeatInterval = 0;
int iRCounter = 0;


// Definition for drmModeGetFB2.
// This is only for some old libdrm library which doesn't support GetFB2 call.
// If the libdrm already contains this, remove the following definition
// ----------------------------------------------------------------------------------
#ifndef drmModeGetFB2
typedef struct _drmModeFB2 {
	uint32_t fb_id;
	uint32_t width, height;
	uint32_t pixel_format; /* fourcc code from drm_fourcc.h */
	uint32_t modifier; /* applies to all buffers */
	uint32_t flags;

	/* per-plane GEM handle; may be duplicate entries for multiple planes */
	uint32_t handles[4];
	uint32_t pitches[4]; /* bytes */
	uint32_t offsets[4]; /* bytes */
} drmModeFB2, *drmModeFB2Ptr;

#define DRM_IOCTL_MODE_GETFB2       DRM_IOWR(0xCE, struct drm_mode_fb_cmd2)
static inline int DRM_IOCTL(int fd, unsigned long cmd, void *arg)
{
	int ret = drmIoctl(fd, cmd, arg);
	return ret < 0 ? -errno : ret;
}

drmModeFB2Ptr
drmModeGetFB2(int fd, uint32_t fb_id)
{
	struct drm_mode_fb_cmd2 get;
	drmModeFB2Ptr ret;
	int err;

	memset(&get, 0, sizeof(get));
	get.fb_id = fb_id;

	err = DRM_IOCTL(fd, DRM_IOCTL_MODE_GETFB2, &get);
	if (err != 0)
		return NULL;

	ret = drmMalloc(sizeof(drmModeFB2));
	if (!ret)
		return NULL;

	ret->fb_id = fb_id;
	ret->width = get.width;
	ret->height = get.height;
	ret->pixel_format = get.pixel_format;
	ret->flags = get.flags;
	ret->modifier = get.modifier[0];
	memcpy(ret->handles, get.handles, sizeof(uint32_t) * 4);
	memcpy(ret->pitches, get.pitches, sizeof(uint32_t) * 4);
	memcpy(ret->offsets, get.offsets, sizeof(uint32_t) * 4);

	return ret;
}

void drmModeFreeFB2(drmModeFB2Ptr ptr)
{
	if (!ptr)
		return;

	/* we might add more frees later. */
	drmFree(ptr);
}
#endif
// ----------------------------------------------------------------------------------

/*
 * Decode the FOURCC code
 * The 'name' must be >=5 bytes long to hold the decoded string
 */
void fourcc_decode(unsigned int code, char *name) 
{
    char a, b, c, d;
    if(!code || !name)
        return;

    a = (char)(code & 0xFF);
    b = (char)(code >> 8 & 0xFF);
    c = (char)(code >> 16 & 0xFF);
    d = (char)(code >> 24 & 0xFF);
    sprintf(name, "%c%c%c%c", a,b,c,d);
}


void dump_buf_file(uint8_t *fb_addr, int len, char *fname)
{
	FILE *fp;
    int rlen = 0;

	fp = fopen(fname, "wb");
	if (!fp) {
		printf("Error opening file: %s, error: %s\n", fname, strerror(errno));
		exit(4);
	}

	rlen = fwrite((void *)fb_addr, len, 1, fp);
    if(rlen <=0) {
        printf("Error writing file (%d/%d)! error: %s\n", rlen, len, strerror(errno));
    }

	fclose(fp);
}

int dump_plane_rgb(uint32_t fd, drmModePlane * ovr)
{
    drmModeFBPtr fb;
    struct drm_mode_map_dumb map = { };
    uint8_t * buf;
    int imgsize;
    char sFile_name[256];
    int ret = 0;

    // Get framebuffer object
    fb = drmModeGetFB(fd, ovr->fb_id);
    if(!fb) {
        printf("Failed to get FB from DRM, error: %s\n", strerror(errno));
        return errno;
    }

	printf("-> Plane/FB: %d/%d, [%d x %d], PITCH:%d, BPP:%d, DEPTH:%d, DETILE:%s\n",
				ovr->plane_id, fb->fb_id, fb->width, fb->height, fb->pitch, fb->bpp, fb->depth,(iFlag & FLAG_TILE)?"Y":"N");

    // Map the framebuffer
    map.handle = fb->handle;
    ret = drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map);
    if (ret) {
        printf("Failed to map the buffer from DRM (%d)! error: %s\n", ret, strerror(errno));
        return errno;
    }

    buf = (uint8_t *) mmap(0,
                 (fb->pitch * fb->height),
                 PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                 map.offset);
    if(!buf) {
        printf("Failed to map the memory! error: %s\n", strerror(errno));
        return errno;
    }

    imgsize = fb->pitch * fb->height;

    // Save to raw 
    if(iFlag & FLAG_TILE) {
        printf("Sorry! De-tile not supported!\n");
        /*
        // Do de-tile
        void *tmp = NULL;
        int size = fb->width * fb->height * fb->bpp / 8;

        tmp = (uint8_t *) malloc(size*8);
        if (!tmp) {
            printf("Failed to alloc memory, size=%d\n", size*8);
            return errno;
        }

        tmp = detile((const void * )buf, NULL, fb->width, fb->height, 4, SUPERTILED, FASTMSAA_SUPERTILE);

        sprintf(sFile_name, "%s/P%d_%dx%d-%d-detile_%04d_FB%d.rgb",sOutput_folder, ovr->plane_id, fb->width, fb->height, fb->bpp, iRCounter+1, ovr->fb_id);
        printf("-> Output: %s (%d)\n", sFile_name, size);
        dump_buf_file((uint8_t *)tmp, size, sFile_name);

        free(tmp);
        //*/
    } else {
        sprintf(sFile_name, "%s/P%d_%dx%d-%d_%04d_FB%d.rgb", sOutput_folder, ovr->plane_id, fb->width, fb->height, fb->bpp, iRCounter+1, ovr->fb_id);
        printf("-> Output: %s (%d)\n", sFile_name, imgsize);
        dump_buf_file(buf, imgsize , sFile_name);
    }
    return 0;
}

int dump_plane_yuv(uint32_t fd, drmModePlane * ovr)
{
	drmModeFB2Ptr fb2;
	struct drm_mode_map_dumb map = { };
	char sBuffer[256];
	unsigned int imgsize;
	//unsigned int ylen, uvlen;
    unsigned int ylenp, uvlenp;
    uint8_t *pSrc_buf=NULL, *pDst_buf=NULL;
    uint8_t *pFb_p0=NULL, *pFb_p1=NULL;
    //unsigned char *nBaseAddr[2];
    int iBpp = 0;
    int ret = 0;
    bool bPacked = false;

    fb2 = drmModeGetFB2(fd, ovr->fb_id);
	if(!fb2) {
		printf("Failed to get FB from DRM, error: %s\n", strerror(errno));
		return errno;
	}

    // Detect the format
    fourcc_decode(fb2->pixel_format, sBuffer);
    sBuffer[4]='\0'; /* terminate */
    switch(fb2->pixel_format) {
        case DRM_FORMAT_NV21:
        case DRM_FORMAT_NV12:
            iBpp = 12;
            bPacked = false;
            break;
        case DRM_FORMAT_YUYV:
        case DRM_FORMAT_YVYU:
        case DRM_FORMAT_UYVY:
        case DRM_FORMAT_VYUY:
            iBpp = 16;
            bPacked = true;
            break;
        default:
            printf("Unsupported format detected: '%s'\n", sBuffer);
            return 1;
    }

    printf("-> Plane/FB: %d/%d, [%d x %d], %s: %s YUV/%s, %dBPP, FMT:%s, MOD:0x%x, DETILE:%s\n",
            ovr->plane_id, ovr->fb_id, fb2->width, fb2->height, sBuffer, bPacked ? "Packed":"Planar", iBpp==12 ? "420" : "422", 
            iBpp, sBuffer, fb2->modifier, (iFlag & FLAG_TILE)?"Y":"N");

    // We calculate the total imgsize barely from the pitch. If it's packed mode, pitches[1] will be 0
	imgsize = fb2->pitches[0] * fb2->height + fb2->pitches[1] * fb2->height / 2;
    pSrc_buf = (uint8_t *)malloc(imgsize);
	if (pSrc_buf == NULL) {
        printf("Failed to alloc memory! error: %s\n", strerror(errno));
		return errno;
    }

	// Map Y planar
	map.handle = fb2->handles[0];
	ret = drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map);
    if (ret) {
        printf("Failed to map the Y buffer from DRM (%d)! error: %s\n", ret, strerror(errno));
        return errno;
    }

	ylenp = fb2->pitches[0] * fb2->height;
	pFb_p0 = (uint8_t *) mmap(0, ylenp, PROT_READ | PROT_WRITE, MAP_SHARED, fd, map.offset);
    if(!pFb_p0) {
        printf("Failed to map the Y memory! error: %s\n", strerror(errno));
        return errno;
    }
	memcpy(pSrc_buf, pFb_p0, ylenp);

    if(!bPacked) {  // Planar mode, process the second plane
	    // Map UV planar
    	map.handle = fb2->handles[1];
	    ret = drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map);
        if (ret) {
            printf("Failed to map the UV buffer from DRM (%d)! error: %s\n", ret, strerror(errno));
            return errno;
        }

        uvlenp = fb2->pitches[1] * fb2->height / 2;
	    pFb_p1 = (uint8_t *) mmap(0, uvlenp, PROT_READ | PROT_WRITE, MAP_SHARED, fd, map.offset);
        if(!pFb_p1) {
            printf("Failed to map the UV memory! error: %s\n", strerror(errno));
            return errno;
        }
	    memcpy(pSrc_buf + ylenp, pFb_p1, uvlenp);
    }

    // Save raw file
    if(iFlag & FLAG_TILE) {
        printf("Sorry! De-tile not supported!\n");

        /*
        if(bPacked) {
            printf("De-tile on packed YUV is not currently supported! Exit...\n");
            return errno;
        }
        // Do de-tile.
        pDst_buf = (uint8_t *)malloc((fb2->width * fb2->height * iBpp) / 8);
    	if (pDst_buf == NULL) {
            printf("Failed to alloc memory! error: %s\n", strerror(errno));
    		return errno;
        }
        nBaseAddr[0] = (unsigned char *)(pFb_p0);
        nBaseAddr[1] = (unsigned char *)(pFb_p1);
        NV12Tile2linear(fb2->width, fb2->height,  0, 0, fb2->pitches[0], nBaseAddr, pDst_buf);

        // Save YUV file
        sprintf(sBuffer, "%s/P%d_%dx%d-%d-detile_%04d_FB%d.yuv",sOutput_folder, ovr->plane_id, fb2->width, fb2->height, iBpp, iRCounter+1, ovr->fb_id);
        printf("-> Output: %s (%d)\n", sBuffer, (fb2->width * fb2->height * iBpp) /8);
    	dump_buf_file(pDst_buf, (fb2->width * fb2->height * iBpp) /8 , sBuffer);
        //*/
    } else {
        sprintf(sBuffer, "%s/P%d_%dx%d-%d_%04d_FB%d.yuv",sOutput_folder, ovr->plane_id, fb2->width, fb2->height, iBpp, iRCounter+1, ovr->fb_id);
        printf("-> Output: %s (%d)\n", sBuffer, imgsize);
    	dump_buf_file(pSrc_buf, imgsize, sBuffer);
    }

    if(!pSrc_buf)
        free(pSrc_buf);
    
    if(!pDst_buf)
        free(pDst_buf);

    return 0;
}

int dump_plane(uint32_t fd, drmModePlane * ovr)
{
    drmModeFBPtr fb;
    fb = drmModeGetFB(fd, ovr->fb_id);
    if(fb && fb->depth > 0)
        return dump_plane_rgb(fd, ovr);
	else
        return dump_plane_yuv(fd, ovr);
}

#ifdef SUPPORT_VBLANK
inline int64_t curTime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000000LL + tv.tv_usec;
}

int64_t wait4vblank(uint32_t fd) {
    union drm_wait_vblank vb;

    int64_t start = curTime();

    vb.request.type = DRM_VBLANK_RELATIVE;
    vb.request.sequence = 1;
    if(drmWaitVBlank(fd, (drmVBlankPtr)&vb))
        return -1;
    
    return curTime()-start;
}
#endif

void showVersion()
{
    printf("Version: %s\n", VERSION);
}

void showUsage(char *prog)
{
    printf("A DRM based screen capture program (%s)\n", VERSION);
    printf("Usage:\n");
    printf("    %s [OP] [ARG] [ARG2]\n", prog);
    printf("[OP] OPeration (optional):\n");
    printf("    -v Show version.\n");
    printf("    -h Show this help information.\n");
    printf("    -i Show information about target DRM device only (no capture).\n");
    printf("    -d DRM device to open. [ARG] should contain the path to the device node. Default: '%s'\n", DEF_DRM_PATH);
    printf("    -o Output folder. [ARG] should contain the path to the output folder. Default: '%s'\n", DEF_OUTPUT_FOLDER);
    printf("    -p Specific plane # to capture. [ARG] should contain the plane number. If no '-p' specified, capture all planes\n");
    printf("    -t Try to de-tile on captured frame, for tile format.\n");
    printf("    -r Repeat mode. [ARG] should contain the repeat count and [ARG2] should contain the interval in ms\n");
    printf("\n");
    printf("Example:\n");
    printf("    %s\n", prog);
    printf("  Capture all planes on default DRM device.\n");
    printf("    %s -d /dev/dri/card1\n", prog);
    printf("  Capture all planes on '/dev/dri/card1' device.\n");
    printf("    %s -p 44 -t -o /sdcard\n", prog);
    printf("  Capture plane 44, do de-tile after capture and then output to /sdcard/.\n");
    printf("    %s -r 30 15\n", prog);
    printf("  Capture 30 frames with interval of 15ms on default DRM device.\n\n");
    printf("Raw buffer capture will be done for each enabled/target plane and one file for each.\nCaptured file will be saved to './' if not specified.\n");
    printf("--- By Gopise, 2023/09\n\n");
    return;
}

int process_cmdline(int argc, char **argv)
{
    int i;
    int ret = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            if(i < argc-1)
                strcpy(sDrm_name, argv[++i]);
            if(strlen(sDrm_name) > 0) {
                printf("\tDevice: Target DRM device: %s\n", sDrm_name);
            } else {
                printf("\tDevice: Error! Unknow target DRM device: %s\n", sDrm_name);
                ret = -1;
                break;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-?") == 0) {
            showUsage(argv[0]);
            ret = -1;
            break;
        } else if (strcmp(argv[i], "-v") == 0) {
            showVersion();
            ret = -1;
            break;
        } else if (strcmp(argv[i], "-i") == 0) {
            printf("\tInfo: Print information only.\n");
            iFlag |= FLAG_PRINT_ONLY;
        } else if (strcmp(argv[i], "-t") == 0) {            
            printf("\tDetile: Try de-tile after capture.\n");
            iFlag |= FLAG_TILE;
        } else if (strcmp(argv[i], "-o") == 0) {
            if(i < argc-1)
                strcpy(sOutput_folder, argv[++i]);
            if(strlen(sOutput_folder) > 0) {
                printf("\tOutput: Output folder: %s\n", sOutput_folder);
            } else {
                printf("\tOutput: Error! Unknow output folder: %s\n", sOutput_folder);
                ret = -1;
                break;
            }
       } else if(strcmp(argv[i], "-p") == 0) {
            if(i < argc-1)
                iTargetPlane = atoi(argv[++i]);
            if(iTargetPlane > 0) {
                printf("\tPlane: Target plane#: %d\n", iTargetPlane);
            } else {
                printf("\tPlane: Error! Unknow target plane %s\n", argv[i]);
                ret = -1;
                break;
            }
       } else if(strcmp(argv[i], "-r") == 0) {
            if(i < argc-1)
                iRepeatCount = atoi(argv[++i]);
            if(i < argc-1)
                iRepeatInterval = atoi(argv[++i]);
            if (iRepeatCount <= 0){
                printf("\tRepeat: Warning! Unknow repeat count '%s', default to %d\n", argv[i], DEF_REPEAT_COUNT);
                iRepeatCount = DEF_REPEAT_COUNT;
            }
            if (iRepeatInterval <= 0){
                printf("\tRepeat: Warning! Unknow repeat interval '%s', default to %d (ms)\n", argv[i], DEF_REPEAT_INTERVAL);
                iRepeatInterval = DEF_REPEAT_INTERVAL;
            }
            printf("\tRepeat: Repeat count: %d, interval: %d\n", iRepeatCount, iRepeatInterval);
            iRCounter = 0;
       } else {
            printf("\tError! Un-recognized parameter: %s\n\n",argv[i]);
            showUsage(argv[0]);
            ret = -1;
        }
    }
    return ret;
}

int main(int argc, char *argv[])
{
	int fd = 0;
	drmModeResPtr res = NULL;
	drmModePlaneResPtr planeres = NULL;
	drmModePlane *ovr[MAX_PLANE];
	int i, ct=0, rt=0;

	printf("[ DRM screen capture ]\n");
    memset(sDrm_name, 0, sizeof(sDrm_name));
    memset(ovr, 0, sizeof(ovr));

    ct = process_cmdline(argc, argv);
    if(ct<0) {
        printf("Invalid parameter!");
        return -1;
    }

    if(strlen(sDrm_name) == 0)
        strcpy(sDrm_name, DEF_DRM_PATH);
    if(strlen(sOutput_folder) == 0)
        strcpy(sOutput_folder, DEF_OUTPUT_FOLDER);

    printf("\nOpening DRM device: %s (0x%x)\n", sDrm_name, iFlag);
    fd = open(sDrm_name, O_RDWR);
	if (fd < 0) {
		printf("Error:Failed to open the drm device (%s): error: %s\n", sDrm_name, strerror(errno));
        rt = -1;
        goto Err;
	}

	drmSetClientCap(fd, DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1);
	res = drmModeGetResources(fd);
	if (res == 0) {
		printf("Failed to get the resources!\n");
        rt = -2;
        goto Err;
	}
	planeres = drmModeGetPlaneResources(fd);
	if (!planeres) {
		printf("Failed to get the plane resources!\n");
        rt = -2;
        goto Err;
	}

    if(planeres->count_planes > MAX_PLANE) {
        printf("Too many planes(%d), cap to %d\n", planeres->count_planes, MAX_PLANE);
        planeres->count_planes = MAX_PLANE;
    }

    do {
        if (!iRCounter) {
        	printf("Total plans: %d\n", planeres->count_planes);
	        printf("%s\t%s\t%s\t%s,%s\t%s,%s\n", "Plane", "CRTC", "FB", "CRTC_x", "CRTC_y", "x", "y");
            printf("=================================================\n");
        }

        ct = 0;
        for (i = 0; i < planeres->count_planes; i++) {
		    ovr[i] = drmModeGetPlane(fd, planeres->planes[i]);
    		if (!ovr[i])
	    		continue;
		    if ((ovr[i]->fb_id > 0) && !iRCounter ) {
        		printf("%d\t%d\t%d\t%d,%d\t\t%d,%d\n",
	    	    	 ovr[i]->plane_id, ovr[i]->crtc_id, ovr[i]->fb_id, ovr[i]->crtc_x,
		    	     ovr[i]->crtc_y, ovr[i]->x, ovr[i]->y);
                ct++;
            }
	    }

        if(!iRCounter)
            printf("Plane(s) enabled: %d\n\n", ct);

        // Print information only
        if(iFlag & FLAG_PRINT_ONLY)
            break;

        if(!iRCounter)
            printf("Dump plane buffer to file ...\n");
        ct = 0;
	    for (i = 0; i < planeres->count_planes; i++) {
		    if (!ovr[i])
			    continue;
    		if ((ovr[i]->fb_id > 0) && (iTargetPlane<0 || iTargetPlane == ovr[i]->plane_id)) {
	    		if(dump_plane(fd, ovr[i])) {
                    printf("Error found! terminating...");
                    break;
                }
                ct ++;
            }
	    }

        if(!ct) {
            printf("No plane found!\n");
            break;
        }

#ifdef SUPPORT_VBLANK
        /* We will wait for next vblank here */
        if(wait4vblank(fd) < 0)
            printf("Wait for VBlank failed: %s (%d) \n", strerror(errno), errno);
#else
        /* fixed wait */
        usleep(iRepeatInterval*1000);
#endif
    } while (++iRCounter < iRepeatCount);

    /* everything's fine, exit */
    goto OK;

Err:
    if(rt == -1 || rt == -2)
    	printf("Try another device through '-d' or refer to the full help message through '-h'\n");

OK:
    if(planeres)
        drmModeFreePlaneResources(planeres);
    if(res)
    	drmModeFreeResources(res);
    if(fd >= 0)
		drmClose(fd);

    if(!rt) {
        printf("\nDone!\n");
    }

	return 0;
}
