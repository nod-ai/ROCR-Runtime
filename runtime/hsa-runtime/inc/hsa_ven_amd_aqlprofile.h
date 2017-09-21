////////////////////////////////////////////////////////////////////////////////
//
// Copyright 2017 ADVANCED MICRO DEVICES, INC.
//
// AMD is granting you permission to use this software and documentation(if any)
// (collectively, the "Materials") pursuant to the terms and conditions of the
// Software License Agreement included with the Materials.If you do not have a
// copy of the Software License Agreement, contact your AMD representative for a
// copy.
//
// You agree that you will not reverse engineer or decompile the Materials, in
// whole or in part, except as allowed by applicable law.
//
// WARRANTY DISCLAIMER : THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND.AMD DISCLAIMS ALL WARRANTIES, EXPRESS, IMPLIED, OR STATUTORY,
// INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON - INFRINGEMENT, THAT THE
// SOFTWARE WILL RUN UNINTERRUPTED OR ERROR - FREE OR WARRANTIES ARISING FROM
// CUSTOM OF TRADE OR COURSE OF USAGE.THE ENTIRE RISK ASSOCIATED WITH THE USE OF
// THE SOFTWARE IS ASSUMED BY YOU.Some jurisdictions do not allow the exclusion
// of implied warranties, so the above exclusion may not apply to You.
//
// LIMITATION OF LIABILITY AND INDEMNIFICATION : AMD AND ITS LICENSORS WILL NOT,
// UNDER ANY CIRCUMSTANCES BE LIABLE TO YOU FOR ANY PUNITIVE, DIRECT,
// INCIDENTAL, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES ARISING FROM USE OF
// THE SOFTWARE OR THIS AGREEMENT EVEN IF AMD AND ITS LICENSORS HAVE BEEN
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.In no event shall AMD's total
// liability to You for all damages, losses, and causes of action (whether in
// contract, tort (including negligence) or otherwise) exceed the amount of $100
// USD.  You agree to defend, indemnify and hold harmless AMD and its licensors,
// and any of their directors, officers, employees, affiliates or agents from
// and against any and all loss, damage, liability and other expenses (including
// reasonable attorneys' fees), resulting from Your use of the Software or
// violation of the terms and conditions of this Agreement.
//
// U.S.GOVERNMENT RESTRICTED RIGHTS : The Materials are provided with
// "RESTRICTED RIGHTS." Use, duplication, or disclosure by the Government is
// subject to the restrictions as set forth in FAR 52.227 - 14 and DFAR252.227 -
// 7013, et seq., or its successor.Use of the Materials by the Government
// constitutes acknowledgement of AMD's proprietary rights in them.
//
// EXPORT RESTRICTIONS: The Materials may be subject to export restrictions as
//                      stated in the Software License Agreement.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef OPENSRC_HSA_RUNTIME_INC_HSA_VEN_AMD_AQLPROFILE_H_
#define OPENSRC_HSA_RUNTIME_INC_HSA_VEN_AMD_AQLPROFILE_H_

#include <stdint.h>
#include "hsa.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

///////////////////////////////////////////////////////////////////////
// Library API:
// The library provides helper methods for instantiation of
// the profile context object and for populating of the start
// and stop AQL packets. The profile object contains a profiling
// events list and needed for profiling buffers descriptors,
// a command buffer and an output data buffer. To check if there
// was an error the library methods return a status code. Also
// the library provides methods for querying required buffers
// attributes, to validate the event attributes and to get profiling
// output data.
//
// Returned status:
//     hsa_status_t – HSA status codes are used from hsa.h header
//
// Supported profiling features:
//
// Supported profiling events
typedef enum {
  HSA_VEN_AMD_AQLPROFILE_EVENT_TYPE_PMC = 0,
  HSA_VEN_AMD_AQLPROFILE_EVENT_TYPE_SQTT = 1
} hsa_ven_amd_aqlprofile_event_type_t;

// Supported performance counters (PMC) blocks
// The block ID is the same for a block instances set, for example
// each block instance from the TCC block set, TCC0, TCC1, …, TCCN
// will have the same block ID HSA_VEN_AMD_AQLPROFILE_BLOCKS_TCC.
#ifndef AQLPROFILE_NGEN_API
typedef enum {
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_CPC    = 0,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_CPF    = 1,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GDS    = 2,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GRBM   = 3,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GRBMSE = 4,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_RMI    = 5,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SPI    = 6,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SQ     = 7,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SQCS   = 8,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SRBM   = 9,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SX     = 10,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TA     = 11,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TCA    = 12,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TCC    = 13,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TCP    = 14,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TD     = 15,
  // MC blocks
  /* HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCARB =   16, */
  /* HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCHUB =   17, */
  /* HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCMCBVM = 18, */
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCSEQ =  19,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCVML2 = 20,
  /* HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCXBAR =  21, */
  /* HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_ATC    = 22, */
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_ATCL2  = 23,
  /* HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GCEA   = 24, */
  /* HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_RPB    = 25, */
  HSA_VEN_AMD_AQLPROFILE_BLOCKS_NUMBER     = 26
} hsa_ven_amd_aqlprofile_block_name_t;
#else  // AQLPROFILE_NGEN_API
typedef enum {
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_CPC = 0,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_CPF = 1,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GDS = 2,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GRBM = 3,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GRBMSE = 4,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SPI = 5,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SQ = 6,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SQCS = 7,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SRBM = 8,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SX = 9,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TA = 10,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TCA = 11,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TCC = 12,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TCP = 13,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_TD = 14,
  // Memory related blocks
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCARB = 15,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCHUB = 16,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCMCBVM = 17,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCSEQ = 18,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCVML2 = 19,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_MCXBAR = 20,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_ATC = 21,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_ATCL2 = 22,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_GCEA = 23,
  HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_RPB = 24,
  HSA_VEN_AMD_AQLPROFILE_BLOCKS_NUMBER = 25
} hsa_ven_amd_aqlprofile_block_name_t;
#endif  // AQLPROFILE_NGEN_API

// PMC event object structure
// ‘counter_id’ value is specified in GFXIPs perfcounter user guides
// which is the counters select value, “Performance Counters Selection”
// chapter.
typedef struct {
  hsa_ven_amd_aqlprofile_block_name_t block_name;
  uint32_t block_index;
  uint32_t counter_id;
} hsa_ven_amd_aqlprofile_event_t;

// Check if event is valid for the specific GPU
hsa_status_t hsa_ven_amd_aqlprofile_validate_event(
    hsa_agent_t agent,                            // HSA handle for the profiling GPU
    const hsa_ven_amd_aqlprofile_event_t* event,  // [in] Pointer on validated event
    bool* result);                                // [out] True if the event valid, False otherwise

// Profiling parameters
// All parameters are generic and if not applicable for a specific
// profile configuration then error status will be returned.
typedef enum {
  // SQTT applicable parameters
  HSA_VEN_AMD_AQLPROFILE_PARAMETER_NAME_COMPUTE_UNIT_TARGET = 0,
  HSA_VEN_AMD_AQLPROFILE_PARAMETER_NAME_VM_ID_MASK = 1,
  HSA_VEN_AMD_AQLPROFILE_PARAMETER_NAME_MASK = 2,
  HSA_VEN_AMD_AQLPROFILE_PARAMETER_NAME_TOKEN_MASK = 3,
  HSA_VEN_AMD_AQLPROFILE_PARAMETER_NAME_TOKEN_MASK2 = 4
} hsa_ven_amd_aqlprofile_parameter_name_t;

// Profile parameter object
typedef struct {
  hsa_ven_amd_aqlprofile_parameter_name_t parameter_name;
  uint32_t value;
} hsa_ven_amd_aqlprofile_parameter_t;

//
// Profile context object:
// The library provides a profile object structure which contains
// the events array, a buffer for the profiling start/stop commands
// and a buffer for the output data.
// The buffers are specified by the buffer descriptors and allocated
// by the application. The buffers allocation attributes, the command
// buffer size, the PMC output buffer size as well as profiling output
// data can be get using the generic get profile info helper _get_info.
//
// Buffer descriptor
typedef struct {
  void* ptr;
  uint32_t size;
} hsa_ven_amd_aqlprofile_descriptor_t;

// Profile context object structure, contains profiling events list and
// needed for profiling buffers descriptors, a command buffer and
// an output data buffer
typedef struct {
  hsa_agent_t agent;                                     // GFXIP handle
  hsa_ven_amd_aqlprofile_event_type_t type;              // Events type
  const hsa_ven_amd_aqlprofile_event_t* events;          // Events array
  uint32_t event_count;                                  // Events count
  const hsa_ven_amd_aqlprofile_parameter_t* parameters;  // Parameters array
  uint32_t parameter_count;                              // Parameters count
  hsa_ven_amd_aqlprofile_descriptor_t output_buffer;     // Output buffer
  hsa_ven_amd_aqlprofile_descriptor_t command_buffer;    // PM4 commands
} hsa_ven_amd_aqlprofile_profile_t;

//
// AQL packets populating methods:
// The helper methods to populate provided by the application START and
// STOP AQL packets which the application is required to submit before and
// after profiled GPU task packets respectively.
//
// AQL Vendor Specific packet which carries a PM4 command
typedef struct {
  uint16_t header;
  uint16_t pm4_command[27];
  hsa_signal_t completion_signal;
} hsa_ext_amd_aql_pm4_packet_t;

// Method to populate the provided AQL packet with profiling start commands
// Only 'pm4_command' fields of the packet are set and the application
// is responsible to set Vendor Specific header type a completion signal
hsa_status_t hsa_ven_amd_aqlprofile_start(
    const hsa_ven_amd_aqlprofile_profile_t* profile,  // [in] profile contex object
    hsa_ext_amd_aql_pm4_packet_t* aql_start_packet);  // [out] profile start AQL packet

// Method to populate the provided AQL packet with profiling stop commands
// Only 'pm4_command' fields of the packet are set and the application
// is responsible to set Vendor Specific header type and a completion signal
hsa_status_t hsa_ven_amd_aqlprofile_stop(
    const hsa_ven_amd_aqlprofile_profile_t* profile,  // [in] profile contex object
    hsa_ext_amd_aql_pm4_packet_t* aql_stop_packet);   // [out] profile stop AQL packet

// Legacy devices, PM4 profiling packet size
const unsigned HSA_VEN_AMD_AQLPROFILE_LEGACY_PM4_PACKET_SIZE = 192;
// Legacy devices, converting the profiling AQL packet to PM4 packet blob
hsa_status_t hsa_ven_amd_aqlprofile_legacy_get_pm4(
    const hsa_ext_amd_aql_pm4_packet_t* aql_packet,  // [in] AQL packet
    void* data);                                     // [out] PM4 packet blob

//
// Get profile info:
// Generic method for getting various profile info including profile buffers
// attributes like the command buffer size and the profiling PMC results.
// It’s implied that all counters are 64bit values.
//
// Profile generic output data:
typedef struct {
  uint32_t sample_id;  // PMC sample of SQTT buffer index
  union {
    struct {
      hsa_ven_amd_aqlprofile_event_t event;  // PMC event
      uint64_t result;                       // PMC result
    } pmc_data;
    hsa_ven_amd_aqlprofile_descriptor_t sqtt_data;  // SQTT output data descriptor
  };
} hsa_ven_amd_aqlprofile_info_data_t;

// Profile attributes
typedef enum {
  HSA_VEN_AMD_AQLPROFILE_INFO_COMMAND_BUFFER_SIZE = 0,  // get_info returns uint32_t value
  HSA_VEN_AMD_AQLPROFILE_INFO_PMC_DATA_SIZE = 1,        // get_info returns uint32_t value
  HSA_VEN_AMD_AQLPROFILE_INFO_PMC_DATA = 2,             // get_info returns PMC uint64_t value
                                                        // in info_data object
  HSA_VEN_AMD_AQLPROFILE_INFO_SQTT_DATA = 3             // get_info returns SQTT buffer ptr/size
                                                        // in info_data object
} hsa_ven_amd_aqlprofile_info_type_t;

// Definition of output data iterator callback
typedef hsa_status_t (*hsa_ven_amd_aqlprofile_data_callback_t)(
    hsa_ven_amd_aqlprofile_info_type_t info_type,   // [in] data type, PMC or SQTT data
    hsa_ven_amd_aqlprofile_info_data_t* info_data,  // [in] info_data object
    void* callback_data);                           // [in/out] data passed to the callback

// Method for getting the profile info
hsa_status_t hsa_ven_amd_aqlprofile_get_info(
    const hsa_ven_amd_aqlprofile_profile_t* profile,  // [in] profile context object
    hsa_ven_amd_aqlprofile_info_type_t attribute,     // [in] requested profile attribute
    void* value);                                     // [in/out] returned value

// Method for iterating the events output data
hsa_status_t hsa_ven_amd_aqlprofile_iterate_data(
    const hsa_ven_amd_aqlprofile_profile_t* profile,  // [in] profile context object
    hsa_ven_amd_aqlprofile_data_callback_t callback,  // [in] callback to iterate the output data
    void* data);                                      // [in/out] data passed to the callback

// Return error string
hsa_status_t hsa_ven_amd_aqlprofile_error_string(
    const char** str);  // [out] pointer on the error string

/**
 * @brief Extension version.
 */
#define hsa_ven_amd_aqlprofile 001000

/**
 * @brief Extension function table.
 */
typedef struct hsa_ven_amd_aqlprofile_1_00_pfn_s {
  hsa_status_t (*hsa_ven_amd_aqlprofile_error_string)(
      const char** str);

  hsa_status_t (*hsa_ven_amd_aqlprofile_validate_event)(
      hsa_agent_t agent,
      const hsa_ven_amd_aqlprofile_event_t* event,
      bool* result);

  hsa_status_t (*hsa_ven_amd_aqlprofile_start)(
      const hsa_ven_amd_aqlprofile_profile_t* profile,
      hsa_ext_amd_aql_pm4_packet_t* aql_start_packet);

  hsa_status_t (*hsa_ven_amd_aqlprofile_stop)(
      const hsa_ven_amd_aqlprofile_profile_t* profile,
      hsa_ext_amd_aql_pm4_packet_t* aql_start_packet);

  hsa_status_t (*hsa_ven_amd_aqlprofile_legacy_get_pm4)(
      const hsa_ext_amd_aql_pm4_packet_t* aql_packet,
      void* data);

  hsa_status_t (*hsa_ven_amd_aqlprofile_get_info)(
      const hsa_ven_amd_aqlprofile_profile_t* profile,
      hsa_ven_amd_aqlprofile_info_type_t attribute,
      void* value);

  hsa_status_t (*hsa_ven_amd_aqlprofile_iterate_data)(
      const hsa_ven_amd_aqlprofile_profile_t* profile,
      hsa_ven_amd_aqlprofile_data_callback_t callback,
      void* data);
} hsa_ven_amd_aqlprofile_1_00_pfn_t;

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // OPENSRC_HSA_RUNTIME_INC_HSA_VEN_AMD_AQLPROFILE_H_
