/* packet-usb-mtp.c
 *
 * usb media transfer protocol dissector
 * Barry Li 2019
 *
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>

#include "packet-usb-mtp.h"


void proto_reg_handoff_usb_mtp(void);
void proto_register_usb_mtp(void);


static int proto_usb_mtp = -1;

//MTP String
static int hf_usb_mtp_num_chars = -1;
static int hf_usb_mtp_string_characters = -1;
//MTP Array & Element List
static int hf_usb_mtp_num_elements = -1;

//Container Dataset
static int hf_usb_mtp_container_length = -1;
static int hf_usb_mtp_container_type = -1;
static int hf_usb_mtp_code = -1;
static int hf_usb_mtp_transaction_id = -1;
static int hf_usb_mtp_payload = -1;

//ObjectPropDesc dataset
static int hf_usb_mtp_object_prop_code = -1;
static int hf_usb_mtp_data_type = -1;
static int hf_usb_mtp_getset = -1;
static int hf_usb_mtp_default_value_uint8 = -1;
static int hf_usb_mtp_default_value_uint16 = -1;
static int hf_usb_mtp_default_value_uint32 = -1;
static int hf_usb_mtp_default_value_uint64 = -1;
static int hf_usb_mtp_default_value_uint128 = -1;
static int hf_usb_mtp_default_value_string = -1;
static int hf_usb_mtp_group_code = -1;
static int hf_usb_mtp_form_flag = -1;
//FORM

//DevicePropDesc dataset
static int hf_usb_mtp_device_property_code = -1;
//hf_usb_mtp_data_type
//hf_usb_mtp_getset
//hf_usb_mtp_default_value
static int hf_usb_mtp_current_value_uint8 = -1;
static int hf_usb_mtp_current_value_uint16 = -1;
static int hf_usb_mtp_current_value_uint32 = -1;
static int hf_usb_mtp_current_value_uint64 = -1;
static int hf_usb_mtp_current_value_uint128 = -1;
static int hf_usb_mtp_current_value_string = -1;
//hf_usb_mtp_form_flag
//FORM

//property value
static int hf_usb_mtp_object_size = -1;
static int hf_usb_mtp_name = -1;
static int hf_usb_mtp_display_name = -1;
static int hf_usb_mtp_date_added = -1;
static int hf_usb_mtp_original_release_date = -1;
static int hf_usb_mtp_persistent_uid = -1;

//StorageInfo Dataset
static int hf_usb_mtp_storage_type = -1;
static int hf_usb_mtp_filesystem_type = -1;
static int hf_usb_mtp_access_capability = -1;
static int hf_usb_mtp_max_capacity = -1;
static int hf_usb_mtp_free_space_in_bytes = -1;
static int hf_usb_mtp_free_space_in_objects = -1;
static int hf_usb_mtp_storage_description = -1;
static int hf_usb_mtp_volume_identifier = -1;

//ObjectInfo Dataset
static int hf_usb_mtp_storage_id = -1;
static int hf_usb_mtp_format = -1;
static int hf_usb_mtp_object_prop_protection_status = -1;
static int hf_usb_mtp_object_compressed_size = -1;
static int hf_usb_mtp_thumb_format = -1;
static int hf_usb_mtp_thumb_compressed_size = -1;
static int hf_usb_mtp_thumb_pix_width = -1;
static int hf_usb_mtp_thumb_pix_height = -1;
static int hf_usb_mtp_image_pix_width = -1;
static int hf_usb_mtp_image_pix_height = -1;
static int hf_usb_mtp_image_bit_depth = -1;
static int hf_usb_mtp_parent_object_handle = -1;
static int hf_usb_mtp_association_type = -1;
static int hf_usb_mtp_association_desc = -1;
static int hf_usb_mtp_sequence_number = -1;
static int hf_usb_mtp_filename = -1;
static int hf_usb_mtp_date_created = -1;
static int hf_usb_mtp_date_modified = -1;
static int hf_usb_mtp_keywords = -1;

//DeviceInfo Dataset
static int hf_usb_mtp_standard_version = -1;
static int hf_usb_mtp_vendor_extension_id = -1;
static int hf_usb_mtp_version = -1;
static int hf_usb_mtp_extensions = -1;
static int hf_usb_mtp_functional_mode = -1;
static int hf_usb_mtp_operations_supported = -1;
static int hf_usb_mtp_events_supported = -1;
static int hf_usb_mtp_device_properties_supported = -1;
static int hf_usb_mtp_capture_formats = -1;
static int hf_usb_mtp_playback_formats = -1;
static int hf_usb_mtp_manufacturer = -1;
static int hf_usb_mtp_model = -1;
static int hf_usb_mtp_device_version = -1;
static int hf_usb_mtp_serial_number = -1;

//others
static int hf_usb_mtp_session_id = -1;
static int hf_usb_mtp_object_handle = -1;
static int hf_usb_mtp_event_code = -1;
static int hf_usb_mtp_object_handle_array = -1;
static int hf_usb_mtp_storage_id_array = -1;
static int hf_usb_mtp_object_prop_code_array = -1;
static int hf_usb_mtp_depth = -1;
static int hf_usb_mtp_element = -1;


static gint ett_usb_mtp = -1;
static gint ett_usb_mtp_payload = -1;
static gint ett_usb_mtp_string = -1;
static gint ett_usb_mtp_array = -1;
static gint ett_usb_mtp_element = -1;


static int hf_pana_response_in = -1;
static int hf_pana_response_to = -1;
static int hf_pana_response_time = -1;


static const value_string mtp_container_type_names_vals[] = {
    {MTP_CONTAINER_TYPE_UNDEFINED,    "Undefined"},
    {MTP_CONTAINER_TYPE_COMMAND,      "Command"},
    {MTP_CONTAINER_TYPE_DATA,         "Data"},
    {MTP_CONTAINER_TYPE_RESPONSE,     "Response"},
    {MTP_CONTAINER_TYPE_EVENT,        "Event"},
    {0, NULL}
};

static const value_string mtp_container_type_names_vals_info[] = {
    {MTP_CONTAINER_TYPE_UNDEFINED,    "UDF"},
    {MTP_CONTAINER_TYPE_COMMAND,      "CMD"},
    {MTP_CONTAINER_TYPE_DATA,         "DAT"},
    {MTP_CONTAINER_TYPE_RESPONSE,     "RES"},
    {MTP_CONTAINER_TYPE_EVENT,        "EVT"},
    {0, NULL}
};

static const value_string mtp_data_type_names_vals[] = {
    {MTP_TYPE_UNDEFINED,      "MTP_TYPE_UNDEFINED"},
    {MTP_TYPE_INT8,           "MTP_TYPE_INT8"},
    {MTP_TYPE_UINT8,          "MTP_TYPE_UINT8"},
    {MTP_TYPE_INT16,          "MTP_TYPE_INT16"},
    {MTP_TYPE_UINT16,         "MTP_TYPE_UINT16"},
    {MTP_TYPE_INT32,          "MTP_TYPE_INT32"},
    {MTP_TYPE_UINT32,         "MTP_TYPE_UINT32"},
    {MTP_TYPE_INT64,          "MTP_TYPE_INT64"},
    {MTP_TYPE_UINT64,         "MTP_TYPE_UINT64"},
    {MTP_TYPE_INT128,         "MTP_TYPE_INT128"},
    {MTP_TYPE_UINT128,        "MTP_TYPE_UINT128"},
    {MTP_TYPE_AINT8,          "MTP_TYPE_AINT8"},
    {MTP_TYPE_AUINT8,         "MTP_TYPE_AUINT8"},
    {MTP_TYPE_AINT16,         "MTP_TYPE_AINT16"},
    {MTP_TYPE_AUINT16,        "MTP_TYPE_AUINT16"},
    {MTP_TYPE_AINT32,         "MTP_TYPE_AINT32"},
    {MTP_TYPE_AUINT32,        "MTP_TYPE_AUINT32"},
    {MTP_TYPE_AINT64,         "MTP_TYPE_AINT64"},
    {MTP_TYPE_AUINT64,        "MTP_TYPE_AUINT64"},
    {MTP_TYPE_AINT128,        "MTP_TYPE_AINT128"},
    {MTP_TYPE_AUINT128,       "MTP_TYPE_AUINT128"},
    {MTP_TYPE_STR,            "MTP_TYPE_STR"},
    {0, NULL}
};

static const value_string mtp_format_names_vals[] = {
    {MTP_FORMAT_UNDEFINED,                            "MTP_FORMAT_UNDEFINED"},
    {MTP_FORMAT_ASSOCIATION,                          "MTP_FORMAT_ASSOCIATION"},
    {MTP_FORMAT_SCRIPT,                               "MTP_FORMAT_SCRIPT"},
    {MTP_FORMAT_EXECUTABLE,                           "MTP_FORMAT_EXECUTABLE"},
    {MTP_FORMAT_TEXT,                                 "MTP_FORMAT_TEXT"},
    {MTP_FORMAT_HTML,                                 "MTP_FORMAT_HTML"},
    {MTP_FORMAT_DPOF,                                 "MTP_FORMAT_DPOF"},
    {MTP_FORMAT_AIFF,                                 "MTP_FORMAT_AIFF"},
    {MTP_FORMAT_WAV,                                  "MTP_FORMAT_WAV"},
    {MTP_FORMAT_MP3,                                  "MTP_FORMAT_MP3"},
    {MTP_FORMAT_AVI,                                  "MTP_FORMAT_AVI"},
    {MTP_FORMAT_MPEG,                                 "MTP_FORMAT_MPEG"},
    {MTP_FORMAT_ASF,                                  "MTP_FORMAT_ASF"},
    {MTP_FORMAT_DEFINED,                              "MTP_FORMAT_DEFINED"},
    {MTP_FORMAT_EXIF_JPEG,                            "MTP_FORMAT_EXIF_JPEG"},
    {MTP_FORMAT_TIFF_EP,                              "MTP_FORMAT_TIFF_EP"},
    {MTP_FORMAT_FLASHPIX,                             "MTP_FORMAT_FLASHPIX"},
    {MTP_FORMAT_BMP,                                  "MTP_FORMAT_BMP"},
    {MTP_FORMAT_CIFF,                                 "MTP_FORMAT_CIFF"},
    {MTP_FORMAT_GIF,                                  "MTP_FORMAT_GIF"},
    {MTP_FORMAT_JFIF,                                 "MTP_FORMAT_JFIF"},
    {MTP_FORMAT_CD,                                   "MTP_FORMAT_CD"},
    {MTP_FORMAT_PICT,                                 "MTP_FORMAT_PICT"},
    {MTP_FORMAT_PNG,                                  "MTP_FORMAT_PNG"},
    {MTP_FORMAT_TIFF,                                 "MTP_FORMAT_TIFF"},
    {MTP_FORMAT_TIFF_IT,                              "MTP_FORMAT_TIFF_IT"},
    {MTP_FORMAT_JP2,                                  "MTP_FORMAT_JP2"},
    {MTP_FORMAT_JPX,                                  "MTP_FORMAT_JPX"},
    {MTP_FORMAT_DNG,                                  "MTP_FORMAT_DNG"},
    {MTP_FORMAT_HEIF,                                 "MTP_FORMAT_HEIF"},
    {MTP_FORMAT_UNDEFINED_FIRMWARE,                   "MTP_FORMAT_UNDEFINED_FIRMWARE"},
    {MTP_FORMAT_WINDOWS_IMAGE_FORMAT,                 "MTP_FORMAT_WINDOWS_IMAGE_FORMAT"},
    {MTP_FORMAT_UNDEFINED_AUDIO,                      "MTP_FORMAT_UNDEFINED_AUDIO"},
    {MTP_FORMAT_WMA,                                  "MTP_FORMAT_WMA"},
    {MTP_FORMAT_OGG,                                  "MTP_FORMAT_OGG"},
    {MTP_FORMAT_AAC,                                  "MTP_FORMAT_AAC"},
    {MTP_FORMAT_AUDIBLE,                              "MTP_FORMAT_AUDIBLE"},
    {MTP_FORMAT_FLAC,                                 "MTP_FORMAT_FLAC"},
    {MTP_FORMAT_UNDEFINED_VIDEO,                      "MTP_FORMAT_UNDEFINED_VIDEO"},
    {MTP_FORMAT_WMV,                                  "MTP_FORMAT_WMV"},
    {MTP_FORMAT_MP4_CONTAINER,                        "MTP_FORMAT_MP4_CONTAINER"},
    {MTP_FORMAT_MP2,                                  "MTP_FORMAT_MP2"},
    {MTP_FORMAT_3GP_CONTAINER,                        "MTP_FORMAT_3GP_CONTAINER"},
    {MTP_FORMAT_UNDEFINED_COLLECTION,                 "MTP_FORMAT_UNDEFINED_COLLECTION"},
    {MTP_FORMAT_ABSTRACT_MULTIMEDIA_ALBUM,            "MTP_FORMAT_ABSTRACT_MULTIMEDIA_ALBUM"},
    {MTP_FORMAT_ABSTRACT_IMAGE_ALBUM,                 "MTP_FORMAT_ABSTRACT_IMAGE_ALBUM"},
    {MTP_FORMAT_ABSTRACT_AUDIO_ALBUM,                 "MTP_FORMAT_ABSTRACT_AUDIO_ALBUM"},
    {MTP_FORMAT_ABSTRACT_VIDEO_ALBUM,                 "MTP_FORMAT_ABSTRACT_VIDEO_ALBUM"},
    {MTP_FORMAT_ABSTRACT_AV_PLAYLIST,                 "MTP_FORMAT_ABSTRACT_AV_PLAYLIST"},
    {MTP_FORMAT_ABSTRACT_CONTACT_GROUP,               "MTP_FORMAT_ABSTRACT_CONTACT_GROUP"},
    {MTP_FORMAT_ABSTRACT_MESSAGE_FOLDER,              "MTP_FORMAT_ABSTRACT_MESSAGE_FOLDER"},
    {MTP_FORMAT_ABSTRACT_CHAPTERED_PRODUCTION,        "MTP_FORMAT_ABSTRACT_CHAPTERED_PRODUCTION"},
    {MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST,              "MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST"},
    {MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST,              "MTP_FORMAT_ABSTRACT_VIDEO_PLAYLIST"},
    {MTP_FORMAT_ABSTRACT_MEDIACAST,                   "MTP_FORMAT_ABSTRACT_MEDIACAST"},
    {MTP_FORMAT_WPL_PLAYLIST,                         "MTP_FORMAT_WPL_PLAYLIST"},
    {MTP_FORMAT_M3U_PLAYLIST,                         "MTP_FORMAT_M3U_PLAYLIST"},
    {MTP_FORMAT_MPL_PLAYLIST,                         "MTP_FORMAT_MPL_PLAYLIST"},
    {MTP_FORMAT_ASX_PLAYLIST,                         "MTP_FORMAT_ASX_PLAYLIST"},
    {MTP_FORMAT_PLS_PLAYLIST,                         "MTP_FORMAT_PLS_PLAYLIST"},
    {MTP_FORMAT_UNDEFINED_DOCUMENT,                   "MTP_FORMAT_UNDEFINED_DOCUMENT"},
    {MTP_FORMAT_ABSTRACT_DOCUMENT,                    "MTP_FORMAT_ABSTRACT_DOCUMENT"},
    {MTP_FORMAT_XML_DOCUMENT,                         "MTP_FORMAT_XML_DOCUMENT"},
    {MTP_FORMAT_MS_WORD_DOCUMENT,                     "MTP_FORMAT_MS_WORD_DOCUMENT"},
    {MTP_FORMAT_MHT_COMPILED_HTML_DOCUMENT,           "MTP_FORMAT_MHT_COMPILED_HTML_DOCUMENT"},
    {MTP_FORMAT_MS_EXCEL_SPREADSHEET,                 "MTP_FORMAT_MS_EXCEL_SPREADSHEET"},
    {MTP_FORMAT_MS_POWERPOINT_PRESENTATION,           "MTP_FORMAT_MS_POWERPOINT_PRESENTATION"},
    {MTP_FORMAT_UNDEFINED_MESSAGE,                    "MTP_FORMAT_UNDEFINED_MESSAGE"},
    {MTP_FORMAT_ABSTRACT_MESSSAGE,                    "MTP_FORMAT_ABSTRACT_MESSSAGE"},
    {MTP_FORMAT_UNDEFINED_CONTACT,                    "MTP_FORMAT_UNDEFINED_CONTACT"},
    {MTP_FORMAT_ABSTRACT_CONTACT,                     "MTP_FORMAT_ABSTRACT_CONTACT"},
    {MTP_FORMAT_VCARD_2,                              "MTP_FORMAT_VCARD_2"},
    {0, NULL}
};

static const value_string mtp_object_prop_code_names_vals[] = {
    {MTP_PROPERTY_STORAGE_ID,                             "MTP_PROPERTY_STORAGE_ID"},
    {MTP_PROPERTY_OBJECT_FORMAT,                          "MTP_PROPERTY_OBJECT_FORMAT"},
    {MTP_PROPERTY_PROTECTION_STATUS,                      "MTP_PROPERTY_PROTECTION_STATUS"},
    {MTP_PROPERTY_OBJECT_SIZE,                            "MTP_PROPERTY_OBJECT_SIZE"},
    {MTP_PROPERTY_ASSOCIATION_TYPE,                       "MTP_PROPERTY_ASSOCIATION_TYPE"},
    {MTP_PROPERTY_ASSOCIATION_DESC,                       "MTP_PROPERTY_ASSOCIATION_DESC"},
    {MTP_PROPERTY_OBJECT_FILE_NAME,                       "MTP_PROPERTY_OBJECT_FILE_NAME"},
    {MTP_PROPERTY_DATE_CREATED,                           "MTP_PROPERTY_DATE_CREATED"},
    {MTP_PROPERTY_DATE_MODIFIED,                          "MTP_PROPERTY_DATE_MODIFIED"},
    {MTP_PROPERTY_KEYWORDS,                               "MTP_PROPERTY_KEYWORDS"},
    {MTP_PROPERTY_PARENT_OBJECT,                          "MTP_PROPERTY_PARENT_OBJECT"},
    {MTP_PROPERTY_ALLOWED_FOLDER_CONTENTS,                "MTP_PROPERTY_ALLOWED_FOLDER_CONTENTS"},
    {MTP_PROPERTY_HIDDEN,                                 "MTP_PROPERTY_HIDDEN"},
    {MTP_PROPERTY_SYSTEM_OBJECT,                          "MTP_PROPERTY_SYSTEM_OBJECT"},
    {MTP_PROPERTY_PERSISTENT_UID,                         "MTP_PROPERTY_PERSISTENT_UID"},
    {MTP_PROPERTY_SYNC_ID,                                "MTP_PROPERTY_SYNC_ID"},
    {MTP_PROPERTY_PROPERTY_BAG,                           "MTP_PROPERTY_PROPERTY_BAG"},
    {MTP_PROPERTY_NAME,                                   "MTP_PROPERTY_NAME"},
    {MTP_PROPERTY_CREATED_BY,                             "MTP_PROPERTY_CREATED_BY"},
    {MTP_PROPERTY_ARTIST,                                 "MTP_PROPERTY_ARTIST"},
    {MTP_PROPERTY_DATE_AUTHORED,                          "MTP_PROPERTY_DATE_AUTHORED"},
    {MTP_PROPERTY_DESCRIPTION,                            "MTP_PROPERTY_DESCRIPTION"},
    {MTP_PROPERTY_URL_REFERENCE,                          "MTP_PROPERTY_URL_REFERENCE"},
    {MTP_PROPERTY_LANGUAGE_LOCALE,                        "MTP_PROPERTY_LANGUAGE_LOCALE"},
    {MTP_PROPERTY_COPYRIGHT_INFORMATION,                  "MTP_PROPERTY_COPYRIGHT_INFORMATION"},
    {MTP_PROPERTY_SOURCE,                                 "MTP_PROPERTY_SOURCE"},
    {MTP_PROPERTY_ORIGIN_LOCATION,                        "MTP_PROPERTY_ORIGIN_LOCATION"},
    {MTP_PROPERTY_DATE_ADDED,                             "MTP_PROPERTY_DATE_ADDED"},
    {MTP_PROPERTY_NON_CONSUMABLE,                         "MTP_PROPERTY_NON_CONSUMABLE"},
    {MTP_PROPERTY_CORRUPT_UNPLAYABLE,                     "MTP_PROPERTY_CORRUPT_UNPLAYABLE"},
    {MTP_PROPERTY_PRODUCER_SERIAL_NUMBER,                 "MTP_PROPERTY_PRODUCER_SERIAL_NUMBER"},
    {MTP_PROPERTY_REPRESENTATIVE_SAMPLE_FORMAT,           "MTP_PROPERTY_REPRESENTATIVE_SAMPLE_FORMAT"},
    {MTP_PROPERTY_REPRESENTATIVE_SAMPLE_SIZE,             "MTP_PROPERTY_REPRESENTATIVE_SAMPLE_SIZE"},
    {MTP_PROPERTY_REPRESENTATIVE_SAMPLE_HEIGHT,           "MTP_PROPERTY_REPRESENTATIVE_SAMPLE_HEIGHT"},
    {MTP_PROPERTY_REPRESENTATIVE_SAMPLE_WIDTH,            "MTP_PROPERTY_REPRESENTATIVE_SAMPLE_WIDTH"},
    {MTP_PROPERTY_REPRESENTATIVE_SAMPLE_DURATION,         "MTP_PROPERTY_REPRESENTATIVE_SAMPLE_DURATION"},
    {MTP_PROPERTY_REPRESENTATIVE_SAMPLE_DATA,             "MTP_PROPERTY_REPRESENTATIVE_SAMPLE_DATA"},
    {MTP_PROPERTY_WIDTH,                                  "MTP_PROPERTY_WIDTH"},
    {MTP_PROPERTY_HEIGHT,                                 "MTP_PROPERTY_HEIGHT"},
    {MTP_PROPERTY_DURATION,                               "MTP_PROPERTY_DURATION"},
    {MTP_PROPERTY_RATING,                                 "MTP_PROPERTY_RATING"},
    {MTP_PROPERTY_TRACK,                                  "MTP_PROPERTY_TRACK"},
    {MTP_PROPERTY_GENRE,                                  "MTP_PROPERTY_GENRE"},
    {MTP_PROPERTY_CREDITS,                                "MTP_PROPERTY_CREDITS"},
    {MTP_PROPERTY_LYRICS,                                 "MTP_PROPERTY_LYRICS"},
    {MTP_PROPERTY_SUBSCRIPTION_CONTENT_ID,                "MTP_PROPERTY_SUBSCRIPTION_CONTENT_ID"},
    {MTP_PROPERTY_PRODUCED_BY,                            "MTP_PROPERTY_PRODUCED_BY"},
    {MTP_PROPERTY_USE_COUNT,                              "MTP_PROPERTY_USE_COUNT"},
    {MTP_PROPERTY_SKIP_COUNT,                             "MTP_PROPERTY_SKIP_COUNT"},
    {MTP_PROPERTY_LAST_ACCESSED,                          "MTP_PROPERTY_LAST_ACCESSED"},
    {MTP_PROPERTY_PARENTAL_RATING,                        "MTP_PROPERTY_PARENTAL_RATING"},
    {MTP_PROPERTY_META_GENRE,                             "MTP_PROPERTY_META_GENRE"},
    {MTP_PROPERTY_COMPOSER,                               "MTP_PROPERTY_COMPOSER"},
    {MTP_PROPERTY_EFFECTIVE_RATING,                       "MTP_PROPERTY_EFFECTIVE_RATING"},
    {MTP_PROPERTY_SUBTITLE,                               "MTP_PROPERTY_SUBTITLE"},
    {MTP_PROPERTY_ORIGINAL_RELEASE_DATE,                  "MTP_PROPERTY_ORIGINAL_RELEASE_DATE"},
    {MTP_PROPERTY_ALBUM_NAME,                             "MTP_PROPERTY_ALBUM_NAME"},
    {MTP_PROPERTY_ALBUM_ARTIST,                           "MTP_PROPERTY_ALBUM_ARTIST"},
    {MTP_PROPERTY_MOOD,                                   "MTP_PROPERTY_MOOD"},
    {MTP_PROPERTY_DRM_STATUS,                             "MTP_PROPERTY_DRM_STATUS"},
    {MTP_PROPERTY_SUB_DESCRIPTION,                        "MTP_PROPERTY_SUB_DESCRIPTION"},
    {MTP_PROPERTY_IS_CROPPED,                             "MTP_PROPERTY_IS_CROPPED"},
    {MTP_PROPERTY_IS_COLOUR_CORRECTED,                    "MTP_PROPERTY_IS_COLOUR_CORRECTED"},
    {MTP_PROPERTY_IMAGE_BIT_DEPTH,                        "MTP_PROPERTY_IMAGE_BIT_DEPTH"},
    {MTP_PROPERTY_F_NUMBER,                               "MTP_PROPERTY_F_NUMBER"},
    {MTP_PROPERTY_EXPOSURE_TIME,                          "MTP_PROPERTY_EXPOSURE_TIME"},
    {MTP_PROPERTY_EXPOSURE_INDEX,                         "MTP_PROPERTY_EXPOSURE_INDEX"},
    {MTP_PROPERTY_TOTAL_BITRATE,                          "MTP_PROPERTY_TOTAL_BITRATE"},
    {MTP_PROPERTY_BITRATE_TYPE,                           "MTP_PROPERTY_BITRATE_TYPE"},
    {MTP_PROPERTY_SAMPLE_RATE,                            "MTP_PROPERTY_SAMPLE_RATE"},
    {MTP_PROPERTY_NUMBER_OF_CHANNELS,                     "MTP_PROPERTY_NUMBER_OF_CHANNELS"},
    {MTP_PROPERTY_AUDIO_BIT_DEPTH,                        "MTP_PROPERTY_AUDIO_BIT_DEPTH"},
    {MTP_PROPERTY_SCAN_TYPE,                              "MTP_PROPERTY_SCAN_TYPE"},
    {MTP_PROPERTY_AUDIO_WAVE_CODEC,                       "MTP_PROPERTY_AUDIO_WAVE_CODEC"},
    {MTP_PROPERTY_AUDIO_BITRATE,                          "MTP_PROPERTY_AUDIO_BITRATE"},
    {MTP_PROPERTY_VIDEO_FOURCC_CODEC,                     "MTP_PROPERTY_VIDEO_FOURCC_CODEC"},
    {MTP_PROPERTY_VIDEO_BITRATE,                          "MTP_PROPERTY_VIDEO_BITRATE"},
    {MTP_PROPERTY_FRAMES_PER_THOUSAND_SECONDS,            "MTP_PROPERTY_FRAMES_PER_THOUSAND_SECONDS"},
    {MTP_PROPERTY_KEYFRAME_DISTANCE,                      "MTP_PROPERTY_KEYFRAME_DISTANCE"},
    {MTP_PROPERTY_BUFFER_SIZE,                            "MTP_PROPERTY_BUFFER_SIZE"},
    {MTP_PROPERTY_ENCODING_QUALITY,                       "MTP_PROPERTY_ENCODING_QUALITY"},
    {MTP_PROPERTY_ENCODING_PROFILE,                       "MTP_PROPERTY_ENCODING_PROFILE"},
    {MTP_PROPERTY_DISPLAY_NAME,                           "MTP_PROPERTY_DISPLAY_NAME"},
    {MTP_PROPERTY_BODY_TEXT,                              "MTP_PROPERTY_BODY_TEXT"},
    {MTP_PROPERTY_SUBJECT,                                "MTP_PROPERTY_SUBJECT"},
    {MTP_PROPERTY_PRIORITY,                               "MTP_PROPERTY_PRIORITY"},
    {MTP_PROPERTY_GIVEN_NAME,                             "MTP_PROPERTY_GIVEN_NAME"},
    {MTP_PROPERTY_MIDDLE_NAMES,                           "MTP_PROPERTY_MIDDLE_NAMES"},
    {MTP_PROPERTY_FAMILY_NAME,                            "MTP_PROPERTY_FAMILY_NAME"},
    {MTP_PROPERTY_PREFIX,                                 "MTP_PROPERTY_PREFIX"},
    {MTP_PROPERTY_SUFFIX,                                 "MTP_PROPERTY_SUFFIX"},
    {MTP_PROPERTY_PHONETIC_GIVEN_NAME,                    "MTP_PROPERTY_PHONETIC_GIVEN_NAME"},
    {MTP_PROPERTY_PHONETIC_FAMILY_NAME,                   "MTP_PROPERTY_PHONETIC_FAMILY_NAME"},
    {MTP_PROPERTY_EMAIL_PRIMARY,                          "MTP_PROPERTY_EMAIL_PRIMARY"},
    {MTP_PROPERTY_EMAIL_PERSONAL_1,                       "MTP_PROPERTY_EMAIL_PERSONAL_1"},
    {MTP_PROPERTY_EMAIL_PERSONAL_2,                       "MTP_PROPERTY_EMAIL_PERSONAL_2"},
    {MTP_PROPERTY_EMAIL_BUSINESS_1,                       "MTP_PROPERTY_EMAIL_BUSINESS_1"},
    {MTP_PROPERTY_EMAIL_BUSINESS_2,                       "MTP_PROPERTY_EMAIL_BUSINESS_2"},
    {MTP_PROPERTY_EMAIL_OTHERS,                           "MTP_PROPERTY_EMAIL_OTHERS"},
    {MTP_PROPERTY_PHONE_NUMBER_PRIMARY,                   "MTP_PROPERTY_PHONE_NUMBER_PRIMARY"},
    {MTP_PROPERTY_PHONE_NUMBER_PERSONAL,                  "MTP_PROPERTY_PHONE_NUMBER_PERSONAL"},
    {MTP_PROPERTY_PHONE_NUMBER_PERSONAL_2,                "MTP_PROPERTY_PHONE_NUMBER_PERSONAL_2"},
    {MTP_PROPERTY_PHONE_NUMBER_BUSINESS,                  "MTP_PROPERTY_PHONE_NUMBER_BUSINESS"},
    {MTP_PROPERTY_PHONE_NUMBER_BUSINESS_2,                "MTP_PROPERTY_PHONE_NUMBER_BUSINESS_2"},
    {MTP_PROPERTY_PHONE_NUMBER_MOBILE,                    "MTP_PROPERTY_PHONE_NUMBER_MOBILE"},
    {MTP_PROPERTY_PHONE_NUMBER_MOBILE_2,                  "MTP_PROPERTY_PHONE_NUMBER_MOBILE_2"},
    {MTP_PROPERTY_FAX_NUMBER_PRIMARY,                     "MTP_PROPERTY_FAX_NUMBER_PRIMARY"},
    {MTP_PROPERTY_FAX_NUMBER_PERSONAL,                    "MTP_PROPERTY_FAX_NUMBER_PERSONAL"},
    {MTP_PROPERTY_FAX_NUMBER_BUSINESS,                    "MTP_PROPERTY_FAX_NUMBER_BUSINESS"},
    {MTP_PROPERTY_PAGER_NUMBER,                           "MTP_PROPERTY_PAGER_NUMBER"},
    {MTP_PROPERTY_PHONE_NUMBER_OTHERS,                    "MTP_PROPERTY_PHONE_NUMBER_OTHERS"},
    {MTP_PROPERTY_PRIMARY_WEB_ADDRESS,                    "MTP_PROPERTY_PRIMARY_WEB_ADDRESS"},
    {MTP_PROPERTY_PERSONAL_WEB_ADDRESS,                   "MTP_PROPERTY_PERSONAL_WEB_ADDRESS"},
    {MTP_PROPERTY_BUSINESS_WEB_ADDRESS,                   "MTP_PROPERTY_BUSINESS_WEB_ADDRESS"},
    {MTP_PROPERTY_INSTANT_MESSANGER_ADDRESS,              "MTP_PROPERTY_INSTANT_MESSANGER_ADDRESS"},
    {MTP_PROPERTY_INSTANT_MESSANGER_ADDRESS_2,            "MTP_PROPERTY_INSTANT_MESSANGER_ADDRESS_2"},
    {MTP_PROPERTY_INSTANT_MESSANGER_ADDRESS_3,            "MTP_PROPERTY_INSTANT_MESSANGER_ADDRESS_3"},
    {MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_FULL,           "MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_FULL"},
    {MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_LINE_1,         "MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_LINE_1"},
    {MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_LINE_2,         "MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_LINE_2"},
    {MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_CITY,           "MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_CITY"},
    {MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_REGION,         "MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_REGION"},
    {MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_POSTAL_CODE,    "MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_POSTAL_CODE"},
    {MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_COUNTRY,        "MTP_PROPERTY_POSTAL_ADDRESS_PERSONAL_COUNTRY"},
    {MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_FULL,           "MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_FULL"},
    {MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_LINE_1,         "MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_LINE_1"},
    {MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_LINE_2,         "MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_LINE_2"},
    {MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_CITY,           "MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_CITY"},
    {MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_REGION,         "MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_REGION"},
    {MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_POSTAL_CODE,    "MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_POSTAL_CODE"},
    {MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_COUNTRY,        "MTP_PROPERTY_POSTAL_ADDRESS_BUSINESS_COUNTRY"},
    {MTP_PROPERTY_POSTAL_ADDRESS_OTHER_FULL,              "MTP_PROPERTY_POSTAL_ADDRESS_OTHER_FULL"},
    {MTP_PROPERTY_POSTAL_ADDRESS_OTHER_LINE_1,            "MTP_PROPERTY_POSTAL_ADDRESS_OTHER_LINE_1"},
    {MTP_PROPERTY_POSTAL_ADDRESS_OTHER_LINE_2,            "MTP_PROPERTY_POSTAL_ADDRESS_OTHER_LINE_2"},
    {MTP_PROPERTY_POSTAL_ADDRESS_OTHER_CITY,              "MTP_PROPERTY_POSTAL_ADDRESS_OTHER_CITY"},
    {MTP_PROPERTY_POSTAL_ADDRESS_OTHER_REGION,            "MTP_PROPERTY_POSTAL_ADDRESS_OTHER_REGION"},
    {MTP_PROPERTY_POSTAL_ADDRESS_OTHER_POSTAL_CODE,       "MTP_PROPERTY_POSTAL_ADDRESS_OTHER_POSTAL_CODE"},
    {MTP_PROPERTY_POSTAL_ADDRESS_OTHER_COUNTRY,           "MTP_PROPERTY_POSTAL_ADDRESS_OTHER_COUNTRY"},
    {MTP_PROPERTY_ORGANIZATION_NAME,                      "MTP_PROPERTY_ORGANIZATION_NAME"},
    {MTP_PROPERTY_PHONETIC_ORGANIZATION_NAME,             "MTP_PROPERTY_PHONETIC_ORGANIZATION_NAME"},
    {MTP_PROPERTY_ROLE,                                   "MTP_PROPERTY_ROLE"},
    {MTP_PROPERTY_BIRTHDATE,                              "MTP_PROPERTY_BIRTHDATE"},
    {MTP_PROPERTY_MESSAGE_TO,                             "MTP_PROPERTY_MESSAGE_TO"},
    {MTP_PROPERTY_MESSAGE_CC,                             "MTP_PROPERTY_MESSAGE_CC"},
    {MTP_PROPERTY_MESSAGE_BCC,                            "MTP_PROPERTY_MESSAGE_BCC"},
    {MTP_PROPERTY_MESSAGE_READ,                           "MTP_PROPERTY_MESSAGE_READ"},
    {MTP_PROPERTY_MESSAGE_RECEIVED_TIME,                  "MTP_PROPERTY_MESSAGE_RECEIVED_TIME"},
    {MTP_PROPERTY_MESSAGE_SENDER,                         "MTP_PROPERTY_MESSAGE_SENDER"},
    {MTP_PROPERTY_ACTIVITY_BEGIN_TIME,                    "MTP_PROPERTY_ACTIVITY_BEGIN_TIME"},
    {MTP_PROPERTY_ACTIVITY_END_TIME,                      "MTP_PROPERTY_ACTIVITY_END_TIME"},
    {MTP_PROPERTY_ACTIVITY_LOCATION,                      "MTP_PROPERTY_ACTIVITY_LOCATION"},
    {MTP_PROPERTY_ACTIVITY_REQUIRED_ATTENDEES,            "MTP_PROPERTY_ACTIVITY_REQUIRED_ATTENDEES"},
    {MTP_PROPERTY_ACTIVITY_OPTIONAL_ATTENDEES,            "MTP_PROPERTY_ACTIVITY_OPTIONAL_ATTENDEES"},
    {MTP_PROPERTY_ACTIVITY_RESOURCES,                     "MTP_PROPERTY_ACTIVITY_RESOURCES"},
    {MTP_PROPERTY_ACTIVITY_ACCEPTED,                      "MTP_PROPERTY_ACTIVITY_ACCEPTED"},
    {MTP_PROPERTY_ACTIVITY_TENTATIVE,                     "MTP_PROPERTY_ACTIVITY_TENTATIVE"},
    {MTP_PROPERTY_ACTIVITY_DECLINED,                      "MTP_PROPERTY_ACTIVITY_DECLINED"},
    {MTP_PROPERTY_ACTIVITY_REMAINDER_TIME,                "MTP_PROPERTY_ACTIVITY_REMAINDER_TIME"},
    {MTP_PROPERTY_ACTIVITY_OWNER,                         "MTP_PROPERTY_ACTIVITY_OWNER"},
    {MTP_PROPERTY_ACTIVITY_STATUS,                        "MTP_PROPERTY_ACTIVITY_STATUS"},
    {MTP_PROPERTY_OWNER,                                  "MTP_PROPERTY_OWNER"},
    {MTP_PROPERTY_EDITOR,                                 "MTP_PROPERTY_EDITOR"},
    {MTP_PROPERTY_WEBMASTER,                              "MTP_PROPERTY_WEBMASTER"},
    {MTP_PROPERTY_URL_SOURCE,                             "MTP_PROPERTY_URL_SOURCE"},
    {MTP_PROPERTY_URL_DESTINATION,                        "MTP_PROPERTY_URL_DESTINATION"},
    {MTP_PROPERTY_TIME_BOOKMARK,                          "MTP_PROPERTY_TIME_BOOKMARK"},
    {MTP_PROPERTY_OBJECT_BOOKMARK,                        "MTP_PROPERTY_OBJECT_BOOKMARK"},
    {MTP_PROPERTY_BYTE_BOOKMARK,                          "MTP_PROPERTY_BYTE_BOOKMARK"},
    {MTP_PROPERTY_LAST_BUILD_DATE,                        "MTP_PROPERTY_LAST_BUILD_DATE"},
    {MTP_PROPERTY_TIME_TO_LIVE,                           "MTP_PROPERTY_TIME_TO_LIVE"},
    {MTP_PROPERTY_MEDIA_GUID,                             "MTP_PROPERTY_MEDIA_GUID"},
    {0, NULL}
};

static const value_string mtp_device_property_code_names_vals[] = {
    {MTP_DEVICE_PROPERTY_UNDEFINED,                       "MTP_DEVICE_PROPERTY_UNDEFINED"},
    {MTP_DEVICE_PROPERTY_BATTERY_LEVEL,                   "MTP_DEVICE_PROPERTY_BATTERY_LEVEL"},
    {MTP_DEVICE_PROPERTY_FUNCTIONAL_MODE,                 "MTP_DEVICE_PROPERTY_FUNCTIONAL_MODE"},
    {MTP_DEVICE_PROPERTY_IMAGE_SIZE,                      "MTP_DEVICE_PROPERTY_IMAGE_SIZE"},
    {MTP_DEVICE_PROPERTY_COMPRESSION_SETTING,             "MTP_DEVICE_PROPERTY_COMPRESSION_SETTING"},
    {MTP_DEVICE_PROPERTY_WHITE_BALANCE,                   "MTP_DEVICE_PROPERTY_WHITE_BALANCE"},
    {MTP_DEVICE_PROPERTY_RGB_GAIN,                        "MTP_DEVICE_PROPERTY_RGB_GAIN"},
    {MTP_DEVICE_PROPERTY_F_NUMBER,                        "MTP_DEVICE_PROPERTY_F_NUMBER"},
    {MTP_DEVICE_PROPERTY_FOCAL_LENGTH,                    "MTP_DEVICE_PROPERTY_FOCAL_LENGTH"},
    {MTP_DEVICE_PROPERTY_FOCUS_DISTANCE,                  "MTP_DEVICE_PROPERTY_FOCUS_DISTANCE"},
    {MTP_DEVICE_PROPERTY_FOCUS_MODE,                      "MTP_DEVICE_PROPERTY_FOCUS_MODE"},
    {MTP_DEVICE_PROPERTY_EXPOSURE_METERING_MODE,          "MTP_DEVICE_PROPERTY_EXPOSURE_METERING_MODE"},
    {MTP_DEVICE_PROPERTY_FLASH_MODE,                      "MTP_DEVICE_PROPERTY_FLASH_MODE"},
    {MTP_DEVICE_PROPERTY_EXPOSURE_TIME,                   "MTP_DEVICE_PROPERTY_EXPOSURE_TIME"},
    {MTP_DEVICE_PROPERTY_EXPOSURE_PROGRAM_MODE,           "MTP_DEVICE_PROPERTY_EXPOSURE_PROGRAM_MODE"},
    {MTP_DEVICE_PROPERTY_EXPOSURE_INDEX,                  "MTP_DEVICE_PROPERTY_EXPOSURE_INDEX"},
    {MTP_DEVICE_PROPERTY_EXPOSURE_BIAS_COMPENSATION,      "MTP_DEVICE_PROPERTY_EXPOSURE_BIAS_COMPENSATION"},
    {MTP_DEVICE_PROPERTY_DATETIME,                        "MTP_DEVICE_PROPERTY_DATETIME"},
    {MTP_DEVICE_PROPERTY_CAPTURE_DELAY,                   "MTP_DEVICE_PROPERTY_CAPTURE_DELAY"},
    {MTP_DEVICE_PROPERTY_STILL_CAPTURE_MODE,              "MTP_DEVICE_PROPERTY_STILL_CAPTURE_MODE"},
    {MTP_DEVICE_PROPERTY_CONTRAST,                        "MTP_DEVICE_PROPERTY_CONTRAST"},
    {MTP_DEVICE_PROPERTY_SHARPNESS,                       "MTP_DEVICE_PROPERTY_SHARPNESS"},
    {MTP_DEVICE_PROPERTY_DIGITAL_ZOOM,                    "MTP_DEVICE_PROPERTY_DIGITAL_ZOOM"},
    {MTP_DEVICE_PROPERTY_EFFECT_MODE,                     "MTP_DEVICE_PROPERTY_EFFECT_MODE"},
    {MTP_DEVICE_PROPERTY_BURST_NUMBER,                    "MTP_DEVICE_PROPERTY_BURST_NUMBER"},
    {MTP_DEVICE_PROPERTY_BURST_INTERVAL,                  "MTP_DEVICE_PROPERTY_BURST_INTERVAL"},
    {MTP_DEVICE_PROPERTY_TIMELAPSE_NUMBER,                "MTP_DEVICE_PROPERTY_TIMELAPSE_NUMBER"},
    {MTP_DEVICE_PROPERTY_TIMELAPSE_INTERVAL,              "MTP_DEVICE_PROPERTY_TIMELAPSE_INTERVAL"},
    {MTP_DEVICE_PROPERTY_FOCUS_METERING_MODE,             "MTP_DEVICE_PROPERTY_FOCUS_METERING_MODE"},
    {MTP_DEVICE_PROPERTY_UPLOAD_URL,                      "MTP_DEVICE_PROPERTY_UPLOAD_URL"},
    {MTP_DEVICE_PROPERTY_ARTIST,                          "MTP_DEVICE_PROPERTY_ARTIST"},
    {MTP_DEVICE_PROPERTY_COPYRIGHT_INFO,                  "MTP_DEVICE_PROPERTY_COPYRIGHT_INFO"},
    {MTP_DEVICE_PROPERTY_SYNCHRONIZATION_PARTNER,         "MTP_DEVICE_PROPERTY_SYNCHRONIZATION_PARTNER"},
    {MTP_DEVICE_PROPERTY_DEVICE_FRIENDLY_NAME,            "MTP_DEVICE_PROPERTY_DEVICE_FRIENDLY_NAME"},
    {MTP_DEVICE_PROPERTY_VOLUME,                          "MTP_DEVICE_PROPERTY_VOLUME"},
    {MTP_DEVICE_PROPERTY_SUPPORTED_FORMATS_ORDERED,       "MTP_DEVICE_PROPERTY_SUPPORTED_FORMATS_ORDERED"},
    {MTP_DEVICE_PROPERTY_DEVICE_ICON,                     "MTP_DEVICE_PROPERTY_DEVICE_ICON"},
    {MTP_DEVICE_PROPERTY_PLAYBACK_RATE,                   "MTP_DEVICE_PROPERTY_PLAYBACK_RATE"},
    {MTP_DEVICE_PROPERTY_PLAYBACK_OBJECT,                 "MTP_DEVICE_PROPERTY_PLAYBACK_OBJECT"},
    {MTP_DEVICE_PROPERTY_PLAYBACK_CONTAINER_INDEX,        "MTP_DEVICE_PROPERTY_PLAYBACK_CONTAINER_INDEX"},
    {MTP_DEVICE_PROPERTY_SESSION_INITIATOR_VERSION_INFO,  "MTP_DEVICE_PROPERTY_SESSION_INITIATOR_VERSION_INFO"},
    {MTP_DEVICE_PROPERTY_PERCEIVED_DEVICE_TYPE,           "MTP_DEVICE_PROPERTY_PERCEIVED_DEVICE_TYPE"},
    {0, NULL}

};

static const value_string mtp_code_names_vals[] = {
    {MTP_OPERATION_GET_DEVICE_INFO,                       "MTP_OPERATION_GET_DEVICE_INFO"},
    {MTP_OPERATION_OPEN_SESSION,                          "MTP_OPERATION_OPEN_SESSION"},
    {MTP_OPERATION_CLOSE_SESSION,                         "MTP_OPERATION_CLOSE_SESSION"},
    {MTP_OPERATION_GET_STORAGE_IDS,                       "MTP_OPERATION_GET_STORAGE_IDS"},
    {MTP_OPERATION_GET_STORAGE_INFO,                      "MTP_OPERATION_GET_STORAGE_INFO"},
    {MTP_OPERATION_GET_NUM_OBJECTS,                       "MTP_OPERATION_GET_NUM_OBJECTS"},
    {MTP_OPERATION_GET_OBJECT_HANDLES,                    "MTP_OPERATION_GET_OBJECT_HANDLES"},
    {MTP_OPERATION_GET_OBJECT_INFO,                       "MTP_OPERATION_GET_OBJECT_INFO"},
    {MTP_OPERATION_GET_OBJECT,                            "MTP_OPERATION_GET_OBJECT"},
    {MTP_OPERATION_GET_THUMB,                             "MTP_OPERATION_GET_THUMB"},
    {MTP_OPERATION_DELETE_OBJECT,                         "MTP_OPERATION_DELETE_OBJECT"},
    {MTP_OPERATION_SEND_OBJECT_INFO,                      "MTP_OPERATION_SEND_OBJECT_INFO"},
    {MTP_OPERATION_SEND_OBJECT,                           "MTP_OPERATION_SEND_OBJECT"},
    {MTP_OPERATION_INITIATE_CAPTURE,                      "MTP_OPERATION_INITIATE_CAPTURE"},
    {MTP_OPERATION_FORMAT_STORE,                          "MTP_OPERATION_FORMAT_STORE"},
    {MTP_OPERATION_RESET_DEVICE,                          "MTP_OPERATION_RESET_DEVICE"},
    {MTP_OPERATION_SELF_TEST,                             "MTP_OPERATION_SELF_TEST"},
    {MTP_OPERATION_SET_OBJECT_PROTECTION,                 "MTP_OPERATION_SET_OBJECT_PROTECTION"},
    {MTP_OPERATION_POWER_DOWN,                            "MTP_OPERATION_POWER_DOWN"},
    {MTP_OPERATION_GET_DEVICE_PROP_DESC,                  "MTP_OPERATION_GET_DEVICE_PROP_DESC"},
    {MTP_OPERATION_GET_DEVICE_PROP_VALUE,                 "MTP_OPERATION_GET_DEVICE_PROP_VALUE"},
    {MTP_OPERATION_SET_DEVICE_PROP_VALUE,                 "MTP_OPERATION_SET_DEVICE_PROP_VALUE"},
    {MTP_OPERATION_RESET_DEVICE_PROP_VALUE,               "MTP_OPERATION_RESET_DEVICE_PROP_VALUE"},
    {MTP_OPERATION_TERMINATE_OPEN_CAPTURE,                "MTP_OPERATION_TERMINATE_OPEN_CAPTURE"},
    {MTP_OPERATION_MOVE_OBJECT,                           "MTP_OPERATION_MOVE_OBJECT"},
    {MTP_OPERATION_COPY_OBJECT,                           "MTP_OPERATION_COPY_OBJECT"},
    {MTP_OPERATION_GET_PARTIAL_OBJECT,                    "MTP_OPERATION_GET_PARTIAL_OBJECT"},
    {MTP_OPERATION_INITIATE_OPEN_CAPTURE,                 "MTP_OPERATION_INITIATE_OPEN_CAPTURE"},
    {MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED,            "MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED"},
    {MTP_OPERATION_GET_OBJECT_PROP_DESC,                  "MTP_OPERATION_GET_OBJECT_PROP_DESC"},
    {MTP_OPERATION_GET_OBJECT_PROP_VALUE,                 "MTP_OPERATION_GET_OBJECT_PROP_VALUE"},
    {MTP_OPERATION_SET_OBJECT_PROP_VALUE,                 "MTP_OPERATION_SET_OBJECT_PROP_VALUE"},
    {MTP_OPERATION_GET_OBJECT_PROP_LIST,                  "MTP_OPERATION_GET_OBJECT_PROP_LIST"},
    {MTP_OPERATION_SET_OBJECT_PROP_LIST,                  "MTP_OPERATION_SET_OBJECT_PROP_LIST"},
    {MTP_OPERATION_GET_INTERDEPENDENT_PROP_DESC,          "MTP_OPERATION_GET_INTERDEPENDENT_PROP_DESC"},
    {MTP_OPERATION_SEND_OBJECT_PROP_LIST,                 "MTP_OPERATION_SEND_OBJECT_PROP_LIST"},
    {MTP_OPERATION_GET_OBJECT_REFERENCES,                 "MTP_OPERATION_GET_OBJECT_REFERENCES"},
    {MTP_OPERATION_SET_OBJECT_REFERENCES,                 "MTP_OPERATION_SET_OBJECT_REFERENCES"},
    {MTP_OPERATION_SKIP,                                  "MTP_OPERATION_SKIP"},

    {MTP_OPERATION_GET_PARTIAL_OBJECT_64,                 "MTP_OPERATION_GET_PARTIAL_OBJECT_64"},
    {MTP_OPERATION_SEND_PARTIAL_OBJECT,                   "MTP_OPERATION_SEND_PARTIAL_OBJECT"},
    {MTP_OPERATION_TRUNCATE_OBJECT,                       "MTP_OPERATION_TRUNCATE_OBJECT"},
    {MTP_OPERATION_BEGIN_EDIT_OBJECT,                     "MTP_OPERATION_BEGIN_EDIT_OBJECT"},
    {MTP_OPERATION_END_EDIT_OBJECT,                       "MTP_OPERATION_END_EDIT_OBJECT"},

    {MTP_RESPONSE_UNDEFINED,                                  "MTP_RESPONSE_UNDEFINED"},
    {MTP_RESPONSE_OK,                                         "MTP_RESPONSE_OK"},
    {MTP_RESPONSE_GENERAL_ERROR,                              "MTP_RESPONSE_GENERAL_ERROR"},
    {MTP_RESPONSE_SESSION_NOT_OPEN,                           "MTP_RESPONSE_SESSION_NOT_OPEN"},
    {MTP_RESPONSE_INVALID_TRANSACTION_ID,                     "MTP_RESPONSE_INVALID_TRANSACTION_ID"},
    {MTP_RESPONSE_OPERATION_NOT_SUPPORTED,                    "MTP_RESPONSE_OPERATION_NOT_SUPPORTED"},
    {MTP_RESPONSE_PARAMETER_NOT_SUPPORTED,                    "MTP_RESPONSE_PARAMETER_NOT_SUPPORTED"},
    {MTP_RESPONSE_INCOMPLETE_TRANSFER,                        "MTP_RESPONSE_INCOMPLETE_TRANSFER"},
    {MTP_RESPONSE_INVALID_STORAGE_ID,                         "MTP_RESPONSE_INVALID_STORAGE_ID"},
    {MTP_RESPONSE_INVALID_OBJECT_HANDLE,                      "MTP_RESPONSE_INVALID_OBJECT_HANDLE"},
    {MTP_RESPONSE_DEVICE_PROP_NOT_SUPPORTED,                  "MTP_RESPONSE_DEVICE_PROP_NOT_SUPPORTED"},
    {MTP_RESPONSE_INVALID_OBJECT_FORMAT_CODE,                 "MTP_RESPONSE_INVALID_OBJECT_FORMAT_CODE"},
    {MTP_RESPONSE_STORAGE_FULL,                               "MTP_RESPONSE_STORAGE_FULL"},
    {MTP_RESPONSE_OBJECT_WRITE_PROTECTED,                     "MTP_RESPONSE_OBJECT_WRITE_PROTECTED"},
    {MTP_RESPONSE_STORE_READ_ONLY,                            "MTP_RESPONSE_STORE_READ_ONLY"},
    {MTP_RESPONSE_ACCESS_DENIED,                              "MTP_RESPONSE_ACCESS_DENIED"},
    {MTP_RESPONSE_NO_THUMBNAIL_PRESENT,                       "MTP_RESPONSE_NO_THUMBNAIL_PRESENT"},
    {MTP_RESPONSE_SELF_TEST_FAILED,                           "MTP_RESPONSE_SELF_TEST_FAILED"},
    {MTP_RESPONSE_PARTIAL_DELETION,                           "MTP_RESPONSE_PARTIAL_DELETION"},
    {MTP_RESPONSE_STORE_NOT_AVAILABLE,                        "MTP_RESPONSE_STORE_NOT_AVAILABLE"},
    {MTP_RESPONSE_SPECIFICATION_BY_FORMAT_UNSUPPORTED,        "MTP_RESPONSE_SPECIFICATION_BY_FORMAT_UNSUPPORTED"},
    {MTP_RESPONSE_NO_VALID_OBJECT_INFO,                       "MTP_RESPONSE_NO_VALID_OBJECT_INFO"},
    {MTP_RESPONSE_INVALID_CODE_FORMAT,                        "MTP_RESPONSE_INVALID_CODE_FORMAT"},
    {MTP_RESPONSE_UNKNOWN_VENDOR_CODE,                        "MTP_RESPONSE_UNKNOWN_VENDOR_CODE"},
    {MTP_RESPONSE_CAPTURE_ALREADY_TERMINATED,                 "MTP_RESPONSE_CAPTURE_ALREADY_TERMINATED"},
    {MTP_RESPONSE_DEVICE_BUSY,                                "MTP_RESPONSE_DEVICE_BUSY"},
    {MTP_RESPONSE_INVALID_PARENT_OBJECT,                      "MTP_RESPONSE_INVALID_PARENT_OBJECT"},
    {MTP_RESPONSE_INVALID_DEVICE_PROP_FORMAT,                 "MTP_RESPONSE_INVALID_DEVICE_PROP_FORMAT"},
    {MTP_RESPONSE_INVALID_DEVICE_PROP_VALUE,                  "MTP_RESPONSE_INVALID_DEVICE_PROP_VALUE"},
    {MTP_RESPONSE_INVALID_PARAMETER,                          "MTP_RESPONSE_INVALID_PARAMETER"},
    {MTP_RESPONSE_SESSION_ALREADY_OPEN,                       "MTP_RESPONSE_SESSION_ALREADY_OPEN"},
    {MTP_RESPONSE_TRANSACTION_CANCELLED,                      "MTP_RESPONSE_TRANSACTION_CANCELLED"},
    {MTP_RESPONSE_SPECIFICATION_OF_DESTINATION_UNSUPPORTED,   "MTP_RESPONSE_SPECIFICATION_OF_DESTINATION_UNSUPPORTED"},
    {MTP_RESPONSE_INVALID_OBJECT_PROP_CODE,                   "MTP_RESPONSE_INVALID_OBJECT_PROP_CODE"},
    {MTP_RESPONSE_INVALID_OBJECT_PROP_FORMAT,                 "MTP_RESPONSE_INVALID_OBJECT_PROP_FORMAT"},
    {MTP_RESPONSE_INVALID_OBJECT_PROP_VALUE,                  "MTP_RESPONSE_INVALID_OBJECT_PROP_VALUE"},
    {MTP_RESPONSE_INVALID_OBJECT_REFERENCE,                   "MTP_RESPONSE_INVALID_OBJECT_REFERENCE"},
    {MTP_RESPONSE_GROUP_NOT_SUPPORTED,                        "MTP_RESPONSE_GROUP_NOT_SUPPORTED"},
    {MTP_RESPONSE_INVALID_DATASET,                            "MTP_RESPONSE_INVALID_DATASET"},
    {MTP_RESPONSE_SPECIFICATION_BY_GROUP_UNSUPPORTED,         "MTP_RESPONSE_SPECIFICATION_BY_GROUP_UNSUPPORTED"},
    {MTP_RESPONSE_SPECIFICATION_BY_DEPTH_UNSUPPORTED,         "MTP_RESPONSE_SPECIFICATION_BY_DEPTH_UNSUPPORTED"},
    {MTP_RESPONSE_OBJECT_TOO_LARGE,                           "MTP_RESPONSE_OBJECT_TOO_LARGE"},
    {MTP_RESPONSE_OBJECT_PROP_NOT_SUPPORTED,                  "MTP_RESPONSE_OBJECT_PROP_NOT_SUPPORTED"},

    {0, NULL}
};

static const value_string mtp_event_code_names_vals[] = {
    {MTP_EVENT_UNDEFINED,                         "MTP_EVENT_UNDEFINED"},
    {MTP_EVENT_CANCEL_TRANSACTION,                "MTP_EVENT_CANCEL_TRANSACTION"},
    {MTP_EVENT_OBJECT_ADDED,                      "MTP_EVENT_OBJECT_ADDED"},
    {MTP_EVENT_OBJECT_REMOVED,                    "MTP_EVENT_OBJECT_REMOVED"},
    {MTP_EVENT_STORE_ADDED,                       "MTP_EVENT_STORE_ADDED"},
    {MTP_EVENT_STORE_REMOVED,                     "MTP_EVENT_STORE_REMOVED"},
    {MTP_EVENT_DEVICE_PROP_CHANGED,               "MTP_EVENT_DEVICE_PROP_CHANGED"},
    {MTP_EVENT_OBJECT_INFO_CHANGED,               "MTP_EVENT_OBJECT_INFO_CHANGED"},
    {MTP_EVENT_DEVICE_INFO_CHANGED,               "MTP_EVENT_DEVICE_INFO_CHANGED"},
    {MTP_EVENT_REQUEST_OBJECT_TRANSFER,           "MTP_EVENT_REQUEST_OBJECT_TRANSFER"},
    {MTP_EVENT_STORE_FULL,                        "MTP_EVENT_STORE_FULL"},
    {MTP_EVENT_DEVICE_RESET,                      "MTP_EVENT_DEVICE_RESET"},
    {MTP_EVENT_STORAGE_INFO_CHANGED,              "MTP_EVENT_STORAGE_INFO_CHANGED"},
    {MTP_EVENT_CAPTURE_COMPLETE,                  "MTP_EVENT_CAPTURE_COMPLETE"},
    {MTP_EVENT_UNREPORTED_STATUS,                 "MTP_EVENT_UNREPORTED_STATUS"},
    {MTP_EVENT_OBJECT_PROP_CHANGED,               "MTP_EVENT_OBJECT_PROP_CHANGED"},
    {MTP_EVENT_OBJECT_PROP_DESC_CHANGED,          "MTP_EVENT_OBJECT_PROP_DESC_CHANGED"},
    {MTP_EVENT_OBJECT_REFERENCES_CHANGED,         "MTP_EVENT_OBJECT_REFERENCES_CHANGED"},
    {0, NULL}
};

static const value_string mtp_storage_type_names_vals[] = {
    {MTP_STORAGE_FIXED_ROM,                       "MTP_STORAGE_FIXED_ROM"},
    {MTP_STORAGE_REMOVABLE_ROM,                   "MTP_STORAGE_REMOVABLE_ROM"},
    {MTP_STORAGE_FIXED_RAM,                       "MTP_STORAGE_FIXED_RAM"},
    {MTP_STORAGE_REMOVABLE_RAM,                   "MTP_STORAGE_REMOVABLE_RAM"},
    {0, NULL}
};

static const value_string mtp_storage_filesystem_names_vals[] = {
    {MTP_STORAGE_FILESYSTEM_FLAT,                 "MTP_STORAGE_FILESYSTEM_FLAT"},
    {MTP_STORAGE_FILESYSTEM_HIERARCHICAL,         "MTP_STORAGE_FILESYSTEM_HIERARCHICAL"},
    {MTP_STORAGE_FILESYSTEM_DCF,                  "MTP_STORAGE_FILESYSTEM_DCF"},
    {0, NULL}
};

static const value_string mtp_storage_access_capability_names_vals[] = {
    {MTP_STORAGE_READ_WRITE,                      "MTP_STORAGE_READ_WRITE"},
    {MTP_STORAGE_READ_ONLY_WITHOUT_DELETE,        "MTP_STORAGE_READ_ONLY_WITHOUT_DELETE"},
    {MTP_STORAGE_READ_ONLY_WITH_DELETE,           "MTP_STORAGE_READ_ONLY_WITH_DELETE"},
    {0, NULL}
};

static const value_string mtp_association_type_names_vals[] = {
    {MTP_ASSOCIATION_TYPE_UNDEFINED,              "MTP_ASSOCIATION_TYPE_UNDEFINED"},
    {MTP_ASSOCIATION_TYPE_GENERIC_FOLDER,         "MTP_ASSOCIATION_TYPE_GENERIC_FOLDER"},
    {0, NULL}
};

static const value_string mtp_association_desc_names_vals[] = {
    {0x0000,    "Undefined"},
    {0x0001,    "Unused by PTP;used by MTP to indicate type of folder"},
    {0x0002,    "Reserved"},
    {0x0003,    "Default Playback Delta"},
    {0x0004,    "Unused"},
    {0x0005,    "Unused"},
    {0x0006,    "Images per row"},
    {0x0007,    "Undefined"},
    {0, NULL}
};

static const value_string mtp_object_prop_protection_status_names_vals[] = {
    {0x0000,    "No protection"},
    {0x0001,    "Read-only"},
    {0x8002,    "Read-only data"},
    {0x8003,    "Non-transferable data"},
    {0, NULL}
};

static const value_string mtp_getset_names_vals[] = {
    {0x00,  "Get"},
    {0x01,  "Get/Set"},
    {0, NULL}
};

static const value_string mtp_formflag_names_vals[] = {
    {0x00,  "None"},
    {0x01,  "Range form"},
    {0x02,  "Enumeration form"},
    {0x03,  "DateTime form"},
    {0x05,  "RegularExpression form"},
    {0x06,  "ByteArray form"},
    {0xFF,  "LongString form"},
    {0, NULL}
};

static const value_string mtp_functional_mode_names_vals[] = {
    {0x0000,    "Standard mode"},
    {0x0001,    "Sleep state"},
    {0xC001,    "Non-responsive playback"},
    {0xC002,    "Responsive playback"},
    {0, NULL}
};


static guint
proto_tree_add_mtp_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, int hfindex, int col_info_append)
{
    guint8 num_chars = 0;
    proto_item *string_item;
    proto_tree *string_tree;

    num_chars = tvb_get_guint8(tvb, offset);
    string_item = proto_tree_add_item(tree, hfindex, tvb, offset, 1+num_chars*2, ENC_LITTLE_ENDIAN);
    string_tree = proto_item_add_subtree(string_item, ett_usb_mtp_string);
    proto_tree_add_item(string_tree, hf_usb_mtp_num_chars, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    if (num_chars>0) {
        proto_tree_add_item(string_tree, hf_usb_mtp_string_characters, tvb, offset+1, num_chars*2, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (col_info_append)
            col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", tvb_get_string_enc(wmem_file_scope(), tvb, offset+1, num_chars*2, ENC_UTF_16 | ENC_LITTLE_ENDIAN));
    }

    return (1 + num_chars*2);
}

static guint
proto_tree_add_mtp_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, int hfindex, int element_hfindex, guint element_size, int col_info_append)
{
    guint32 i, num_elements = 0;
    proto_item *array_item, *element_item;
    proto_tree *array_tree;

    num_elements = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    array_item = proto_tree_add_item(tree, hfindex, tvb, offset, 4 + element_size * num_elements, ENC_NA);
    array_tree = proto_item_add_subtree(array_item, ett_usb_mtp_array);
    proto_tree_add_item(array_tree, hf_usb_mtp_num_elements, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    for (i=0; i<num_elements; i++) {
        element_item = proto_tree_add_item(array_tree, element_hfindex, tvb, offset+4+element_size*i, element_size, ENC_LITTLE_ENDIAN);
        //proto_item_append_text(element_item, "%d", i+1);
    }

    if (col_info_append)
        col_append_fstr(pinfo->cinfo, COL_INFO, "  %u", num_elements);

    return offset + 4 + element_size*num_elements;
}


static void
dissect_usb_mtp_bulk_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, usb_mtp_conv_info_t *usb_mtp_conv_info, guint16 mtp_code, guint16 mtp_transaction_id)
{
    guint32 mtp_format;
    guint32 mtp_prop = 0;
    usb_mtp_transaction_t *usb_mtp_trans;

    switch (mtp_code) {
        case MTP_OPERATION_OPEN_SESSION:
            proto_tree_add_item(tree, hf_usb_mtp_session_id, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            break;
        case MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED:
            proto_tree_add_item(tree, hf_usb_mtp_format, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            mtp_format = tvb_get_guint32(tvb, 12, ENC_LITTLE_ENDIAN);
            col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", val_to_str_const(mtp_format, mtp_format_names_vals, "Unknown"));
            break;
        case MTP_OPERATION_GET_DEVICE_PROP_DESC:
            proto_tree_add_item(tree, hf_usb_mtp_device_property_code, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", val_to_str_const(tvb_get_guint32(tvb, 12, ENC_LITTLE_ENDIAN), mtp_device_property_code_names_vals, "Unknown"));
            break;
        case MTP_OPERATION_GET_STORAGE_INFO:
            proto_tree_add_item(tree, hf_usb_mtp_storage_id, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            break;
        case MTP_OPERATION_GET_OBJECT_HANDLES:
            proto_tree_add_item(tree, hf_usb_mtp_storage_id, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_format, tvb, 16, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_parent_object_handle, tvb, 20, 4, ENC_LITTLE_ENDIAN);
            break;
        case MTP_OPERATION_GET_OBJECT_PROP_VALUE:
        case MTP_OPERATION_SET_OBJECT_PROP_VALUE:
            proto_tree_add_item(tree, hf_usb_mtp_object_handle, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_object_prop_code, tvb, 16, 4, ENC_LITTLE_ENDIAN);
            mtp_prop = tvb_get_guint16(tvb, 16, ENC_LITTLE_ENDIAN);
            col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", val_to_str_const(mtp_prop, mtp_object_prop_code_names_vals, "Unknown prop"));
            break;
        case MTP_OPERATION_GET_OBJECT_PROP_DESC:
            proto_tree_add_item(tree, hf_usb_mtp_object_prop_code, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_format, tvb, 16, 4, ENC_LITTLE_ENDIAN);
            mtp_prop = tvb_get_guint16(tvb, 12, ENC_LITTLE_ENDIAN);
            col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", val_to_str_const(mtp_prop, mtp_object_prop_code_names_vals, "Unknown prop"));
            break;
        case MTP_OPERATION_GET_OBJECT_INFO:
        case MTP_OPERATION_GET_OBJECT_REFERENCES:
        case MTP_OPERATION_GET_OBJECT:
            proto_tree_add_item(tree, hf_usb_mtp_object_handle, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  %u", tvb_get_guint32(tvb, 12, ENC_LITTLE_ENDIAN));
            break;
        case MTP_OPERATION_GET_OBJECT_PROP_LIST:
            proto_tree_add_item(tree, hf_usb_mtp_object_handle, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_format, tvb, 16, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_object_prop_code, tvb, 20, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_group_code, tvb, 24, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_depth, tvb, 28, 4, ENC_LITTLE_ENDIAN);
            break;
        case MTP_OPERATION_SEND_OBJECT_INFO:
            proto_tree_add_item(tree, hf_usb_mtp_storage_id, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_parent_object_handle, tvb, 16, 4, ENC_LITTLE_ENDIAN);
            break;
        case MTP_OPERATION_DELETE_OBJECT:
            proto_tree_add_item(tree, hf_usb_mtp_object_handle, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_format, tvb,16, 4, ENC_LITTLE_ENDIAN);
            break;
    }

    if (!PINFO_FD_VISITED(pinfo) &&
        (mtp_code == MTP_OPERATION_GET_OBJECT_PROP_DESC ||
         mtp_code == MTP_OPERATION_GET_OBJECT_PROP_VALUE ||
         mtp_code == MTP_OPERATION_SET_OBJECT_PROP_VALUE)) {

        usb_mtp_trans = wmem_new(wmem_file_scope(), usb_mtp_transaction_t);
        usb_mtp_trans->req_frame = pinfo->num;
        usb_mtp_trans->rep_frame = 0;
        usb_mtp_trans->req_time = pinfo->fd->abs_ts;
        usb_mtp_trans->mtp_prop = mtp_prop;
        wmem_map_insert(usb_mtp_conv_info->transaction_map, GUINT_TO_POINTER(mtp_transaction_id), (void *)usb_mtp_trans);
    }

    return;
}

static gint
proto_tree_add_mtp_object_prop_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint start, guint16 mtp_prop, int col_info_append)
{
    guint16 mtp_format = 0;
    guint16 mtp_data_uint16 = 0;
    guint32 mtp_storage_id = 0;
    guint64 mtp_object_size = 0;
    gint prop_len = 0;

    switch(mtp_prop) {
        case MTP_PROPERTY_OBJECT_FORMAT:
            prop_len = 2;
            proto_tree_add_item(tree, hf_usb_mtp_format, tvb, start, 2, ENC_LITTLE_ENDIAN);
            mtp_format = tvb_get_guint16(tvb, start, ENC_LITTLE_ENDIAN);
            if (col_info_append)
                col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", val_to_str_const(mtp_format, mtp_format_names_vals, "Unknown format"));
            break;
        case MTP_PROPERTY_STORAGE_ID:
            prop_len = 4;
            proto_tree_add_item(tree, hf_usb_mtp_storage_id, tvb, start, 4, ENC_LITTLE_ENDIAN);
            mtp_storage_id = tvb_get_guint32(tvb, start, ENC_LITTLE_ENDIAN);
            if (col_info_append)
                col_append_fstr(pinfo->cinfo, COL_INFO, "  0x%08X", mtp_storage_id);
            break;
        case MTP_PROPERTY_OBJECT_SIZE:
            prop_len = 8;
            proto_tree_add_item(tree, hf_usb_mtp_object_size, tvb, start, 8, ENC_LITTLE_ENDIAN);
            mtp_object_size = tvb_get_guint64(tvb, start, ENC_LITTLE_ENDIAN);
            if (col_info_append)
                col_append_fstr(pinfo->cinfo, COL_INFO, "  %ull", mtp_object_size);
            break;
        case MTP_PROPERTY_PROTECTION_STATUS:
            prop_len = 2;
            proto_tree_add_item(tree, hf_usb_mtp_object_prop_protection_status, tvb, start, 2, ENC_LITTLE_ENDIAN);
            mtp_data_uint16 = tvb_get_guint16(tvb, start, ENC_LITTLE_ENDIAN);
            if (col_info_append)
                col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", val_to_str_const(mtp_data_uint16, mtp_object_prop_protection_status_names_vals, "Reserved"));
            break;
        case MTP_PROPERTY_PERSISTENT_UID:
            prop_len = 16;
            proto_tree_add_item(tree, hf_usb_mtp_persistent_uid, tvb, start, 16, ENC_LITTLE_ENDIAN);
            break;
        case MTP_PROPERTY_NAME:
            prop_len = proto_tree_add_mtp_string(tvb, pinfo, tree, start, hf_usb_mtp_name, col_info_append);
            break;
        case MTP_PROPERTY_DISPLAY_NAME:
            prop_len = proto_tree_add_mtp_string(tvb, pinfo, tree, start, hf_usb_mtp_display_name, col_info_append);
            break;
        case MTP_PROPERTY_OBJECT_FILE_NAME:
            prop_len = proto_tree_add_mtp_string(tvb, pinfo, tree, start, hf_usb_mtp_filename, col_info_append);
            break;
        case MTP_PROPERTY_DATE_MODIFIED:
            prop_len = proto_tree_add_mtp_string(tvb, pinfo, tree, start, hf_usb_mtp_date_modified, col_info_append);
            break;
        case MTP_PROPERTY_DATE_ADDED:
            prop_len = proto_tree_add_mtp_string(tvb, pinfo, tree, start, hf_usb_mtp_date_added, col_info_append);
            break;
        case MTP_PROPERTY_ORIGINAL_RELEASE_DATE:
            prop_len = proto_tree_add_mtp_string(tvb, pinfo, tree, start, hf_usb_mtp_original_release_date, col_info_append);
            break;
        default:
            prop_len = 0;

    }

    return prop_len;

}

static void
proto_tree_add_mtp_object_prop_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16 mtp_data_type = 0;
    guint offset = 0;

    proto_tree_add_item(tree, hf_usb_mtp_object_prop_code, tvb, 12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mtp_data_type, tvb, 14, 2, ENC_LITTLE_ENDIAN);
    mtp_data_type = tvb_get_guint16(tvb, 14, ENC_LITTLE_ENDIAN);
    col_append_sep_str(pinfo->cinfo, COL_INFO, "  ", val_to_str_const(mtp_data_type, mtp_data_type_names_vals, "Unkown"));
    proto_tree_add_item(tree, hf_usb_mtp_getset, tvb, 16, 1, ENC_LITTLE_ENDIAN);

    offset = 17;
    switch(mtp_data_type){
        case MTP_TYPE_UINT8:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint8, tvb, 17, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case MTP_TYPE_UINT16:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint16, tvb, 17, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case MTP_TYPE_UINT32:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint32, tvb, 17, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case MTP_TYPE_UINT64:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint64, tvb, 17, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case MTP_TYPE_UINT128:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint128, tvb, 17, 16, ENC_LITTLE_ENDIAN);
            offset += 16;
            break;
        case MTP_TYPE_STR:
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, 17, hf_usb_mtp_default_value_string, 0);
            break;
    }
    proto_tree_add_item(tree, hf_usb_mtp_group_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mtp_form_flag, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);

}

static void
proto_tree_add_mtp_device_prop_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16 mtp_data_type = 0;
    guint offset = 0;

    proto_tree_add_item(tree, hf_usb_mtp_device_property_code, tvb, 12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mtp_data_type, tvb, 14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mtp_getset, tvb, 16, 1, ENC_LITTLE_ENDIAN);
    offset = 17;

    mtp_data_type = tvb_get_guint16(tvb, 14, ENC_LITTLE_ENDIAN);
    switch(mtp_data_type){
        case MTP_TYPE_UINT8:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint8, tvb, 17, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_current_value_uint8, tvb, 18, 1, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case MTP_TYPE_UINT16:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint16, tvb, 17, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_current_value_uint16, tvb, 19, 2, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case MTP_TYPE_UINT32:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint32, tvb, 17, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_current_value_uint32, tvb, 21, 4, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case MTP_TYPE_UINT64:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint64, tvb, 17, 8, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_current_value_uint64, tvb, 25, 8, ENC_LITTLE_ENDIAN);
            offset += 16;
            break;
        case MTP_TYPE_UINT128:
            proto_tree_add_item(tree, hf_usb_mtp_default_value_uint128, tvb, 17, 16, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_current_value_uint128, tvb, 33, 16, ENC_LITTLE_ENDIAN);
            offset += 32;
            break;
        case MTP_TYPE_STR:
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, 17, hf_usb_mtp_default_value_string, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_current_value_string, 0);
            break;
    }
    proto_tree_add_item(tree, hf_usb_mtp_form_flag, tvb, offset, 1, ENC_NA);

}

static void
proto_tree_add_mtp_object_prop_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint i, num_of_elements, offset, data_len, str_len, prop_len;
    guint16 mtp_data_type, mtp_prop;
    proto_item *element_item;
    proto_tree *element_tree;

    proto_tree_add_item(tree, hf_usb_mtp_num_elements, tvb, 12, 4, ENC_LITTLE_ENDIAN);
    num_of_elements = tvb_get_guint32(tvb, 12, ENC_LITTLE_ENDIAN);

    offset = 16;
    for (i=0; i<num_of_elements; i++) {
        mtp_prop = tvb_get_guint16(tvb, offset+4, ENC_LITTLE_ENDIAN);
        mtp_data_type = tvb_get_guint16(tvb, offset+6, ENC_LITTLE_ENDIAN);
        if (mtp_data_type == MTP_TYPE_UINT8)
            data_len = 1;
        else if (mtp_data_type == MTP_TYPE_UINT16)
            data_len = 2;
        else if (mtp_data_type == MTP_TYPE_UINT32)
            data_len = 4;
        else if (mtp_data_type == MTP_TYPE_UINT64)
            data_len = 8;
        else if (mtp_data_type == MTP_TYPE_UINT128)
            data_len = 16;
        else if (mtp_data_type == MTP_TYPE_STR) {
            str_len  = tvb_get_guint8(tvb, offset+8);
            data_len = 1 + str_len * 2;
        }

        element_item = proto_tree_add_item(tree, hf_usb_mtp_element, tvb, offset, 8+data_len, ENC_NA);
        proto_item_append_text(element_item, "%d", i+1);
        element_tree = proto_item_add_subtree(element_item, ett_usb_mtp_element);

        proto_tree_add_item(element_tree, hf_usb_mtp_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_tree, hf_usb_mtp_object_prop_code, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_tree, hf_usb_mtp_data_type, tvb, offset+6, 2, ENC_LITTLE_ENDIAN);

        offset += 8;
        prop_len = proto_tree_add_mtp_object_prop_value(tvb, pinfo, element_tree, offset, mtp_prop, 0);
        if (prop_len > 0) {
            offset += prop_len;
            continue;
        }
        switch(mtp_data_type){
            case MTP_TYPE_UINT8:
                proto_tree_add_item(element_tree, hf_usb_mtp_current_value_uint8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                break;
            case MTP_TYPE_UINT16:
                proto_tree_add_item(element_tree, hf_usb_mtp_current_value_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                break;
            case MTP_TYPE_UINT32:
                proto_tree_add_item(element_tree, hf_usb_mtp_current_value_uint32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case MTP_TYPE_UINT64:
                proto_tree_add_item(element_tree, hf_usb_mtp_current_value_uint64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                break;
            case MTP_TYPE_UINT128:
                proto_tree_add_item(element_tree, hf_usb_mtp_current_value_uint128, tvb, offset, 16, ENC_LITTLE_ENDIAN);
                break;
            case MTP_TYPE_STR:
                proto_tree_add_mtp_string(tvb, pinfo, element_tree, offset, hf_usb_mtp_current_value_string, 0);
                break;
        }
        offset += data_len;

    }

}

static void
dissect_usb_mtp_bulk_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, usb_mtp_conv_info_t *usb_mtp_conv_info, guint16 mtp_code, guint16 mtp_transaction_id)
{
    usb_mtp_transaction_t *usb_mtp_trans;
    guint16 mtp_prop = 0;
    guint offset = 0;


    if (mtp_code == MTP_OPERATION_GET_OBJECT_PROP_DESC ||
        mtp_code == MTP_OPERATION_GET_OBJECT_PROP_VALUE ||
        mtp_code == MTP_OPERATION_SET_OBJECT_PROP_VALUE) {
        usb_mtp_trans = (usb_mtp_transaction_t *)wmem_map_lookup(usb_mtp_conv_info->transaction_map, GUINT_TO_POINTER(mtp_transaction_id));
        if (usb_mtp_trans) {
            mtp_prop = usb_mtp_trans->mtp_prop;
        }
    }


    switch (mtp_code) {
        case MTP_OPERATION_OPEN_SESSION:
            proto_tree_add_item(tree, hf_usb_mtp_session_id, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            break;
        case MTP_OPERATION_GET_OBJECT_PROP_DESC:
            proto_tree_add_mtp_object_prop_desc(tvb, pinfo, tree);
            break;
        case MTP_OPERATION_GET_DEVICE_PROP_DESC:
            proto_tree_add_mtp_device_prop_desc(tvb, pinfo, tree);
            break;
        case MTP_OPERATION_GET_OBJECT_PROP_VALUE:
        case MTP_OPERATION_SET_OBJECT_PROP_VALUE:
            proto_tree_add_mtp_object_prop_value(tvb, pinfo, tree, 12, mtp_prop, 0);
            break;
        case MTP_OPERATION_GET_OBJECT_PROP_LIST:
            proto_tree_add_mtp_object_prop_list(tvb, pinfo, tree);
            break;
        case MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED:
            proto_tree_add_mtp_array(tvb, pinfo, tree, 12, hf_usb_mtp_object_prop_code_array, hf_usb_mtp_object_prop_code, 2, 1);
            break;
        case MTP_OPERATION_GET_STORAGE_IDS:
            proto_tree_add_mtp_array(tvb, pinfo, tree, 12, hf_usb_mtp_storage_id_array, hf_usb_mtp_storage_id, 4, 1);
            break;
        case MTP_OPERATION_GET_OBJECT_HANDLES:
        case MTP_OPERATION_GET_OBJECT_REFERENCES:
            proto_tree_add_mtp_array(tvb, pinfo, tree, 12, hf_usb_mtp_object_handle_array, hf_usb_mtp_object_handle, 4, 1);
            break;
        case MTP_OPERATION_GET_STORAGE_INFO:
            proto_tree_add_item(tree, hf_usb_mtp_storage_type, tvb, 12, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_filesystem_type, tvb, 14, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_access_capability, tvb, 16, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_max_capacity, tvb, 18, 8, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_free_space_in_bytes, tvb, 26, 8, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_free_space_in_objects, tvb, 34, 4, ENC_LITTLE_ENDIAN);
            offset = 38;
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_storage_description, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_volume_identifier, 0);
            break;
        case MTP_OPERATION_GET_OBJECT_INFO:
        case MTP_OPERATION_SEND_OBJECT_INFO:
            proto_tree_add_item(tree, hf_usb_mtp_storage_id, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_format, tvb, 16, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_object_prop_protection_status, tvb, 18, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_object_compressed_size, tvb, 20, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_thumb_format, tvb, 24, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_thumb_compressed_size, tvb, 26, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_thumb_pix_width, tvb, 30, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_thumb_pix_height, tvb, 34, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_image_pix_width, tvb, 38, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_image_pix_height, tvb, 42, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_image_bit_depth, tvb, 46, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_parent_object_handle, tvb, 50, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_association_type, tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_association_desc, tvb, 56, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_sequence_number, tvb, 60, 4, ENC_LITTLE_ENDIAN);
            offset = 64;
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_filename, 1);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_date_created, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_date_modified, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_keywords, 0);
            break;
        case MTP_OPERATION_GET_DEVICE_INFO:
            proto_tree_add_item(tree, hf_usb_mtp_standard_version, tvb, 12, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_vendor_extension_id, tvb, 14, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_mtp_version, tvb, 18, 2, ENC_LITTLE_ENDIAN);
            offset = 20;
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_extensions, 0);
            proto_tree_add_item(tree, hf_usb_mtp_functional_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            offset = proto_tree_add_mtp_array(tvb, pinfo, tree, offset, hf_usb_mtp_operations_supported, hf_usb_mtp_code, 2, 0);
            offset = proto_tree_add_mtp_array(tvb, pinfo, tree, offset, hf_usb_mtp_events_supported, hf_usb_mtp_event_code, 2, 0);
            offset = proto_tree_add_mtp_array(tvb, pinfo, tree, offset, hf_usb_mtp_device_properties_supported, hf_usb_mtp_device_property_code, 2, 0);
            offset = proto_tree_add_mtp_array(tvb, pinfo, tree, offset, hf_usb_mtp_capture_formats, hf_usb_mtp_format, 2, 0);
            offset = proto_tree_add_mtp_array(tvb, pinfo, tree, offset, hf_usb_mtp_playback_formats, hf_usb_mtp_format, 2, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_manufacturer, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_model, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_device_version, 0);
            offset += proto_tree_add_mtp_string(tvb, pinfo, tree, offset, hf_usb_mtp_serial_number, 0);
            break;

    }

}

/* dissector for usb media transfer protocol bulk data */
static int
dissect_usb_mtp_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    gint length;
    proto_tree *tree;
    proto_item *ti;
    proto_item *payload_item;
    proto_tree *payload_tree;
    guint16 mtp_container_type;
    guint16 mtp_code;
    guint16 mtp_transaction_id;
    usb_mtp_conv_info_t *usb_mtp_conv_info;
    conversation_t *conversation;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;

    conversation = find_or_create_conversation(pinfo);
    usb_mtp_conv_info = (usb_mtp_conv_info_t *)conversation_get_proto_data(conversation, proto_usb_mtp);
    if (!usb_mtp_conv_info) {
        /*
                 * No.  Attach that information to the conversation, and add
         * it to the list of information structures.
         */
        usb_mtp_conv_info = wmem_new(wmem_file_scope(), usb_mtp_conv_info_t);
        usb_mtp_conv_info->transaction_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(conversation, proto_usb_mtp, usb_mtp_conv_info);
    }

    length = tvb_reported_length(tvb);

    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_PROTOCOL, "USBMTP");

    ti = proto_tree_add_protocol_format(parent_tree, proto_usb_mtp, tvb, 0, -1, "USB Media Transfer Protocol");
    tree = proto_item_add_subtree(ti, ett_usb_mtp);

    proto_tree_add_item(tree, hf_usb_mtp_container_length, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mtp_container_type, tvb, 4, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mtp_code, tvb, 6, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mtp_transaction_id, tvb, 8, 4, ENC_LITTLE_ENDIAN);

    mtp_container_type = tvb_get_guint16(tvb, 4, ENC_LITTLE_ENDIAN);
    mtp_code = tvb_get_guint16(tvb, 6, ENC_LITTLE_ENDIAN);
    mtp_transaction_id = tvb_get_guint16(tvb, 8, ENC_LITTLE_ENDIAN);
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(mtp_container_type, mtp_container_type_names_vals_info, "Unknown type"));
    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", val_to_str_const(mtp_code, mtp_code_names_vals, "Unknown code"));

    if (length <= 12)
        return tvb_captured_length(tvb);

    payload_item = proto_tree_add_item(tree, hf_usb_mtp_payload, tvb, 12, -1, ENC_NA);
    payload_tree = proto_item_add_subtree(payload_item, ett_usb_mtp_payload);

    if (mtp_container_type == MTP_CONTAINER_TYPE_COMMAND)
        dissect_usb_mtp_bulk_cmd(tvb ,pinfo, payload_tree, usb_mtp_conv_info, mtp_code, mtp_transaction_id);
    else if (mtp_container_type == MTP_CONTAINER_TYPE_DATA)
        dissect_usb_mtp_bulk_data(tvb ,pinfo, payload_tree, usb_mtp_conv_info, mtp_code, mtp_transaction_id);

    return tvb_captured_length(tvb);
}

static gboolean
dissect_usb_mtp_bulk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint packet_len;
    guint32 mtp_len;
    guint16 mtp_type;
    guint16 mtp_code;

    packet_len = tvb_reported_length(tvb);
    if (packet_len < 12)
        return FALSE;

    mtp_len = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN);
    if (mtp_len < 12 || packet_len != mtp_len)
        return FALSE;

    mtp_type = tvb_get_guint16(tvb, 4, ENC_LITTLE_ENDIAN);
    if (mtp_type > 4)
        return FALSE;

    mtp_code = tvb_get_guint16(tvb, 6, ENC_LITTLE_ENDIAN);
    if ( ( 0x1001 <= mtp_code && mtp_code <= 0x101C ) ||
         ( 0x2000 <= mtp_code && mtp_code <= 0x2020 ) ||
         ( 0x9801 <= mtp_code && mtp_code <= 0x9820 ) ||
         ( 0xA801 <= mtp_code && mtp_code <= 0xA808 ) ) {

        dissect_usb_mtp_bulk(tvb, pinfo, tree, data);
        return TRUE;
    }

    return FALSE;
}

void
proto_register_usb_mtp(void)
{
    static hf_register_info hf[] = {

//MTP String
        { &hf_usb_mtp_num_chars, { "NumChars", "usbmtp.num.chars", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_string_characters, { "String Characters", "usbmtp.string.characters", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }},
//MTP Array
        { &hf_usb_mtp_num_elements, { "NumElements", "usbmtp.num.elements", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

//Container Dataset
        { &hf_usb_mtp_container_length, { "ContainerLength", "usbmtp.container.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_container_type, { "ContainerType", "usbmtp.container.type", FT_UINT16, BASE_HEX, VALS(mtp_container_type_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_code, { "Code", "usbmtp.code", FT_UINT16, BASE_HEX, VALS(mtp_code_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_transaction_id, { "TransactionID", "usbmtp.transaction.id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_payload, { "Payload", "usbmtp.payload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

//ObjectPropDesc dataset
        { &hf_usb_mtp_object_prop_code, { "ObjectPropCode", "usbmtp.object.prop.code", FT_UINT16, BASE_HEX, VALS(mtp_object_prop_code_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_data_type, { "Datatype", "usbmtp.datatype", FT_UINT16, BASE_HEX, VALS(mtp_data_type_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_getset, { "Get/Set", "usbmtp.getset", FT_UINT8, BASE_HEX, VALS(mtp_getset_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_default_value_uint8, { "Default Value", "usbmtp.default.value.uint8", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_default_value_uint16, { "Default Value", "usbmtp.default.value.uint16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_default_value_uint32, { "Default Value", "usbmtp.default.value.uint32", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_default_value_uint64, { "Default Value", "usbmtp.default.value.uint64", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_default_value_uint128, { "Default Value", "usbmtp.default.value.uint128", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_default_value_string, { "Default Value", "usbmtp.default.value.string", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_group_code, { "Group Code", "usbmtp.groupcode", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_form_flag, { "Form Flag", "usbmtp.formflag", FT_UINT8, BASE_HEX, VALS(mtp_formflag_names_vals), 0x0, NULL, HFILL }},
        //FORM

//DevicePropDesc dataset
        { &hf_usb_mtp_device_property_code, { "Device Property Code", "usbmtp.device.property.code", FT_UINT16, BASE_HEX, VALS(mtp_device_property_code_names_vals), 0x0, NULL, HFILL }},
        //hf_usb_mtp_data_type
        //hf_usb_mtp_getset
        //hf_usb_mtp_default_value
        { &hf_usb_mtp_current_value_uint8, { "Current Value", "usbmtp.current.value.uint8", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_current_value_uint16, { "Current Value", "usbmtp.current.value.uint16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_current_value_uint32, { "Current Value", "usbmtp.current.value.uint32", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_current_value_uint64, { "Current Value", "usbmtp.current.value.uint64", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_current_value_uint128, { "Current Value", "usbmtp.current.value.uint128", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_current_value_string, { "Current Value", "usbmtp.current.value.string", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        //hf_usb_mtp_form_flag
        //FORM

//property value
        { &hf_usb_mtp_object_size, { "Object size(Byte)", "usbmtp.object.size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_name, { "Name", "usbmtp.name", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_display_name, { "Display Name", "usbmtp.display.name", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_date_added, { "Date Added", "usbmtp.date.added", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_original_release_date, { "Original Release Date", "usbmtp.original.release.date", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_persistent_uid, { "Persistent UID", "usbmtp.persistent.uid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

//StorageInfo Dataset
        { &hf_usb_mtp_storage_type, { "Storage Type", "usbmtp.storage.type", FT_UINT16, BASE_HEX, VALS(mtp_storage_type_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_filesystem_type, { "Filesystem Type", "usbmtp.filesystem.type", FT_UINT16, BASE_HEX, VALS(mtp_storage_filesystem_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_access_capability, { "Access Capability", "usbmtp.access.capability", FT_UINT16, BASE_HEX, VALS(mtp_storage_access_capability_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_max_capacity, { "Max Capacity", "usbmtp.max.capacity", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_free_space_in_bytes, { "Free Space In Bytes", "usbmtp.free.space.in.bytes", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_free_space_in_objects, { "Free Space In Objects", "usbmtp.free.space.in.objects", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_storage_description, { "Storage Description", "usbmtp.storage.description", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_volume_identifier, { "Volume Identifier", "usbmtp.volume.identifier", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

//ObjectInfo Dataset
        { &hf_usb_mtp_storage_id, { "StorageID", "usbmtp.storage.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_format, { "ObjecFormatCode", "usbmtp.format", FT_UINT16, BASE_HEX, VALS(mtp_format_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_object_prop_protection_status, { "Protection Status", "usbmtp.object.prop.protection.status", FT_UINT16, BASE_HEX, VALS(mtp_object_prop_protection_status_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_object_compressed_size, { "Object Compressed Size", "usbmtp.object.compressed.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_thumb_format, { "*Thumb Format", "usbmtp.thumb.format", FT_UINT16, BASE_HEX, VALS(mtp_format_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_thumb_compressed_size, { "*Thumb Compressed Size", "usbmtp.thumb.compressed.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_thumb_pix_width, { "*Thumb Pix Width", "usbmtp.thumb.pix.width", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_thumb_pix_height, { "*Thumb Pix Height", "usbmtp.thumb.pix.height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_image_pix_width, { "Image Pix Width", "usbmtp.image.width", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_image_pix_height, { "Image Pix Height", "usbmtp.image.height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_image_bit_depth, { "Image Bit Depth", "usbmtp.image.height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_parent_object_handle, { "Parent ObjectHandle", "usbmtp.parent.object.handle", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_association_type, { "Association Type", "usbmtp.association.type", FT_UINT16, BASE_HEX, VALS(mtp_association_type_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_association_desc, { "Association Description", "usbmtp.association.desc", FT_UINT32, BASE_HEX, VALS(mtp_association_desc_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_sequence_number, { "*Sequence Number", "usbmtp.sequence.number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_filename, { "Filename", "usbmtp.filename", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_date_created, { "Date Created", "usbmtp.date.created", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_date_modified, { "Data Modified", "usbmtp.date.modified", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_keywords, { "Keywords", "usbmtp.keywords", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

//DeviceInfo Dataset
        { &hf_usb_mtp_standard_version, { "Standard Version", "usbmtp.standard.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_vendor_extension_id, { "MTP Vendor Extension ID", "usbmtp.vendor.extension.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_version, { "MTP Version", "usbmtp.version", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_extensions, { "MTP Extensions", "usbmtp.extensions", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_functional_mode, { "Functional Mode", "usbmtp.functional.mode", FT_UINT16, BASE_HEX, VALS(mtp_functional_mode_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_operations_supported, { "Operations Supported", "usbmtp.operations.supported", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_events_supported, { "Events Supported", "usbmtp.events.supported", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_device_properties_supported, { "Device Properties Supported", "usbmtp.device.properties.supported", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_capture_formats, { "Capture Formats", "usbmtp.capture.formats", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_playback_formats, { "Playback Formats", "usbmtp.playback.formats", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_manufacturer, { "Manufacturer", "usbmtp.manufacturer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_model, { "Model", "usbmtp.model", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_device_version, { "Device Version", "usbmtp.device.version", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_serial_number, { "Serial Number", "usbmtp.serial.number", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

//others
        { &hf_usb_mtp_session_id, { "Session ID", "usbmtp.session.id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_object_handle, { "ObjectHandle", "usbmtp.object.handle", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_event_code, { "Event Code", "usbmtp.event.code", FT_UINT16, BASE_HEX, VALS(mtp_event_code_names_vals), 0x0, NULL, HFILL }},
        { &hf_usb_mtp_object_handle_array, { "ObjectHandle array", "usbmtp.object.handle.array", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_storage_id_array, { "StorageID array", "usbmtp.storage.id.array", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_object_prop_code_array, { "ObjectPropCode Array", "usbmtp.object.prop.code.array", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_depth, { "Depth", "usbmtp.depth", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_usb_mtp_element, { "Element", "usbmtp.element", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    };

    static gint *usb_mtp_subtrees[] = {
                &ett_usb_mtp,
                &ett_usb_mtp_payload,
                &ett_usb_mtp_string,
                &ett_usb_mtp_array,
                &ett_usb_mtp_element,
    };

    proto_usb_mtp = proto_register_protocol("USB Media Transfer Protocol", "USBMTP", "usbmtp");
    proto_register_field_array(proto_usb_mtp, hf, array_length(hf));
    proto_register_subtree_array(usb_mtp_subtrees, array_length(usb_mtp_subtrees));
}

void
proto_reg_handoff_usb_mtp(void)
{
    heur_dissector_add("usb.bulk", dissect_usb_mtp_bulk_heur, "MTP USB bulk endpoint", "mtp_usb_bulk", proto_usb_mtp, HEURISTIC_ENABLE);
}

