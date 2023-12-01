# drmcap
A debugging tool for screen capture under DRM (Direct Render Manager)

This is a debugging tool for screen capture under DRM (Direct Render Manager).
This also a revised version for previous “drmfbcap” (DRM Framebuffer Capture).

Unlike the FB based system under which we can capture the frame buffer easily through reading the device node, the DRM is much more complex and secure-protected. No direct way for reading framebuffer data from user space.
Under DRM case, we need to open the DRM device, query the resource, get and map the FB object and then read the buffer eventually.

With this tool, we can capture the buffer content from a DRM device and output as raw RGB/YUV data.
Features:

Capture all planes or specific plane, including hidden/covered planes or planes (overlays) managed by applications directly.
Both RGB and YUV supported (auto detect).
Tile format (VSI Super-Tile) is also supported.
Repeat mode which can capture frames continuously.
Tool was built as static linked, in this case, it should be working in both Linux and Android.

 

Important notes:

Behavior of DRM subsystem is different between Linux 4.x and 5.x/6.x.

For Linux 4.x, you can capture the RGB buffer without any problem. But, there’s no API for YUV (multi-plane) buffer.
To capture YUV, please patch kernel with: “kernel_0001-drm-Add-getfb2-ioctl_L4.14.98.patch”.

For Linux 5.x, mapping/capturing the internal buffer is not allowed by default due to security reason. To overcome this temporary (for debug only), patch the kernel with: “0001-drm-enable-mapping-of-internal-object-for-debugging_L5.x.patch”. It contains a minor change to remove this guard.

Both patches are included in attachment.

To get more details about how to use this tool, try “-h” option to print the usage message.

Enjoy!
