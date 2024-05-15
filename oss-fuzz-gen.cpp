#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "libusb/libusb.h"
#include "libusb/libusbi.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider stream(data, size);
  libusb_context *ctx = nullptr;
  libusb_device_handle *handle = nullptr;
  libusb_bos_descriptor *bos = nullptr;
  int ret;

  ret = libusb_init(&ctx);
  if (ret < 0) {
    return ret;
  }

  handle = libusb_open_device_with_vid_pid(ctx, stream.ConsumeIntegral<uint16_t>(),
                                            stream.ConsumeIntegral<uint16_t>());
  if (!handle) {
    goto cleanup;
  }

  ret = libusb_get_bos_descriptor(handle, &bos);
  if (ret < 0) {
    goto cleanup;
  }

  libusb_free_bos_descriptor(bos);

cleanup:
  if (handle) {
    libusb_close(handle);
  }
  if (ctx) {
    libusb_exit(ctx);
  }
  return 0;
}