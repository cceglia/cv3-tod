/*
 * The Rust boundary of the CV3 TOD shim.
 *
 * Everything here is the contract between `src/ffi.rs` and `cv3_tod.c`: one action per step, the
 * small enums both sides number identically, and the accessors Rust exports. The class harness
 * includes this header too, so its stubs cannot drift from the layout the shim really uses.
 *
 * No protocol code belongs here. A `Cv3Action` is either one USB transfer the core wants performed
 * or the operation's final result.
 */
#pragma once

#include <glib.h>

typedef struct _Cv3Tod Cv3Tod;

typedef enum
{
  CV3_ACTION_OUT = 0,
  CV3_ACTION_INTERRUPT_IN = 1,
  CV3_ACTION_BULK_IN = 2,
  CV3_ACTION_CONTROL = 3,
  CV3_ACTION_FINISH = 4,
  /* The finger event: an interrupt read, and the only transfer submitted cancellable. */
  CV3_ACTION_WAIT_FINGER = 5,
} Cv3ActionKind;

typedef enum
{
  CV3_IO_COMPLETED = 0,
  CV3_IO_DATA = 1,
  CV3_IO_FAILED = 2,
} Cv3IoResult;

typedef enum
{
  CV3_IO_ERROR_TIMEOUT = 0,
  CV3_IO_ERROR_DISCONNECTED = 1,
  CV3_IO_ERROR_CANCELLED = 2,
  CV3_IO_ERROR_BUSY = 3,
  CV3_IO_ERROR_STALL = 4,
  CV3_IO_ERROR_OTHER = 5,
} Cv3IoError;

/* Matches cv3_tod::plugin::OutcomeKind. */
typedef enum
{
  CV3_FINISH_OK = 0,
  CV3_FINISH_GENERAL = 1,
  CV3_FINISH_PROTO = 2,
  CV3_FINISH_BUSY = 3,
  CV3_FINISH_REMOVED = 4,
  /* The sensor answered a verdict, but not a match for the print asked about. */
  CV3_FINISH_NO_MATCH = 5,
  /* No finger arrived: libfprint carries this as a retry, not a device error. */
  CV3_FINISH_RETRY = 6,
  /* The operation's cancellable was cancelled; libfprint's task already knows. */
  CV3_FINISH_CANCELLED = 7,
  CV3_FINISH_DATA_INVALID = 8,
  CV3_FINISH_DATA_NOT_FOUND = 9,
} Cv3FinishKind;

/* Must match cv3_tod::ffi::Cv3Action, which static-asserts the same size and offsets. */
typedef struct
{
  guint32  kind;
  guint8   endpoint;
  guint8   request_type;
  guint8   request;
  /* One when this transfer must be submitted with the action's cancellable. */
  guint8   cancellable;
  guint16  value;
  guint16  index;
  guint32  timeout_ms;
  guint8  *buffer;
  gsize    length;
  gint32   status;
  gint32   error_code;
  char     message[256];
} Cv3Action;

_Static_assert (sizeof (Cv3Action) == 296,
                "Cv3Action must match cv3-tod's #[repr(C)] layout");
_Static_assert (G_STRUCT_OFFSET (Cv3Action, cancellable) == 7,
                "Cv3Action.cancellable must stay at offset 7");
_Static_assert (G_STRUCT_OFFSET (Cv3Action, message) == 40,
                "Cv3Action.message must stay at offset 40");

/* One print of an identification gallery. `data` is the print's `fpi-data`, borrowed for the
 * duration of cv3_tod_identify_start (which decodes it synchronously); `index` is its position in
 * libfprint's gallery, which the shim needs to report the exact FpPrint. */
typedef struct
{
  const guint8 *data;
  gsize         length;
  guint32       index;
} Cv3GalleryEntry;

_Static_assert (sizeof (Cv3GalleryEntry) == 24,
                "Cv3GalleryEntry must match cv3-tod's #[repr(C)] layout");
_Static_assert (G_STRUCT_OFFSET (Cv3GalleryEntry, length) == 8,
                "Cv3GalleryEntry.length must stay at offset 8");
_Static_assert (G_STRUCT_OFFSET (Cv3GalleryEntry, index) == 16,
                "Cv3GalleryEntry.index must stay at offset 16");

Cv3Tod *cv3_tod_create (void);
void cv3_tod_destroy (Cv3Tod *tod);
Cv3Action cv3_tod_open_start (Cv3Tod *tod);
Cv3Action cv3_tod_on_transfer (Cv3Tod *tod,
                               guint32 result,
                               guint32 error,
                               gsize   actual_length);
Cv3Action cv3_tod_close_start (Cv3Tod *tod);
gint32 cv3_tod_enrol_stages (void);
Cv3Action cv3_tod_enrol_start (Cv3Tod *tod);
gint32 cv3_tod_take_progress (Cv3Tod *tod, gint32 *completed);
gsize cv3_tod_take_payload (Cv3Tod *tod, guint8 *destination, gsize capacity);
Cv3Action cv3_tod_verify_start (Cv3Tod *tod, const guint8 *payload, gsize length);
Cv3Action cv3_tod_identify_start (Cv3Tod *tod,
                                  const Cv3GalleryEntry *entries,
                                  gsize count);
gint64 cv3_tod_take_match (Cv3Tod *tod);
