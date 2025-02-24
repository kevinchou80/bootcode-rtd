/*
 * Display Setup
 */
#define CONFIG_DISPLAY_PORT 			1	// 0: single port, 1: double port
#define CONFIG_DISPLAY_COLOR_BITS 		1	// 0: 30bits, 1:24 bits, 2: 30bits

#define CONFIG_DISPLAY_EVEN_RSV1_BIT 	0	// 0: Indicate 0, 1: Indicate 1
#define CONFIG_DISPLAY_ODD_RSV1_BIT		0 	// 0: Indicate 0, 1: Indicate 1
#define CONFIG_DISPLAY_BITMAPPING_TABLE	0 // 0: Table1, 1:Table2

#define CONFIG_DISPLAY_PORTAB_SWAP		1	// 0: No Swap, 1: Swap
#define CONFIG_DISPLAY_RED_BLUE_SWAP	0	// 0: No Swap, 1: Swap
#define CONFIG_DISPLAY_MSB_LSB_SWAP		0	// 0: No Swap, 1: Swap
#define CONFIG_DISPLAY_SKEW_DATA_OUTPUT 0	// 0: Disable, 1: Skew data output
#define CONFIG_DISPLAY_OUTPUT_INVERSE	0	// 0: No Swap, 1: Swap

/*
 * Display Sync Output polarity
 */
 #define CONFIG_DISPLAY_VERTICAL_SYNC_NORMAL 	0	// 0: normal, 1: Invert
#define CONFIG_DISPLAY_HORIZONTAL_SYNC_NORMAL 	0 	// 0: normal, 1: Invert
#define CONFIG_DISPLAY_VERTICAL_SYNC 			0	// 0: normal, 1: Invert
#define CONFIG_DISPLAY_HORIZONTAL_SYNC 			0 	// 0: normal, 1: Invert
#define CONFIG_DISPLAY_CLOCK_INVERSE			0	// 0: No inverse, 1: inverse
#define CONFIG_DISPLAY_RATIO_4X3 				0	// 0: 16:9 , 1: 4:3
#define CONFIG_DISPLAY_CLOCK_MIN 				126	//Not fine tune
#define CONFIG_DISPLAY_CLOCK_MAX 				160//reynold 091126  //154	//hpwang 20071119
#define CONFIG_DISPLAY_CLOCK_TYPICAL 			148*1000000	//hpwang 20071119
#define CONFIG_DISPLAY_REFRESH_RATE				60

/*
 * Display total window setup
 */
#define CONFIG_DISP_HORIZONTAL_TOTAL 			2139 // 2259//2299//reynold 091126 //2199
#define CONFIG_DISP_VERTICAL_TOTAL 				1125
//
#define CONFIG_DISP_VERTICAL_TOTAL_50Hz_MIN 			1308	//Not fine tune
#define CONFIG_DISP_VERTICAL_TOTAL_50Hz_MAX 			1380	//Not fine tune
#define CONFIG_DISP_VERTICAL_TOTAL_60Hz_MIN 			1100	//Not fine tune
#define CONFIG_DISP_VERTICAL_TOTAL_60Hz_MAX 			1149 	//Not fine tune

/*
 * Display Sync Width setup
 */
#define CONFIG_DISP_HSYNC_WIDTH 				22//31
#define CONFIG_DISP_VSYNC_LENGTH 				5

/*
 * Display Enable window setup
 */
#define CONFIG_DISP_DEN_STA_HPOS 141
#define CONFIG_DISP_DEN_END_HPOS 2061
#define CONFIG_DISP_DEN_STA_VPOS 10
#define CONFIG_DISP_DEN_END_VPOS 1090


/*
 * Display active window setup
 */
#define CONFIG_DISP_ACT_STA_HPOS 0
#define CONFIG_DISP_ACT_END_HPOS 1920
#define CONFIG_DISP_ACT_STA_VPOS 0
#define CONFIG_DISP_ACT_END_VPOS 1080
#define CONFIG_DISP_HSYNC_LASTLINE 2139
#define CONFIG_DISP_DCLK_DELAY 0

#define _CONFIG_DISP_ACT_STA_BIOS 			0x00
#define CONFIG_DEFAULT_DPLL_M_DIVIDER		0xb2
#define CONFIG_DEFAULT_DPLL_N_DIVIDER		0x18

// CSW+ 0970617 For panel power on sequence
/////////////////////////////
//Off --> On Sequence
/////////////////////////////
#define	PANEL_TO_LVDS_ON_ms		25		 // Delay(T1+T2): Panel Power --> LVDS Signal
#define	LVDS_TO_LIGHT_ON_ms		1000	//550      // Delay(T3):    Settings: LVDS Signal --> Backlight On
/////////////////////////////
//On --> Off	Sequence
/////////////////////////////
#define	LIGHT_TO_LDVS_OFF_ms		150  // Delay(T4):    Turn Off backlight and delay to turn off LVDS signal
#define	LVDS_TO_PANEL_OFF_ms		0   // Delay(T5+T6): LVDS Signal Off --> Panel Power Off
////////////////////////////
//Panel Off--> Next On
////////////////////////////
#define	PANEL_OFF_TO_ON_ms		550     // Delay(T7):    Totally Off --> Next On

////////////////////////////
//Backlight
////////////////////////////
#define CONFIG_BACKLIGHT_PWM_FREQ				100	//PAL:100Hz, NTSC:120Hz
#define CONFIG_BACKLIGHT_PWM_DUTY				32	//Toshiba: 12.5%
#define FIX_LAST_LINE_ENABLE 0
#define FIX_LAST_LINE_4X_ENABLE 0
////////////////////////////
//VFLIP Switch
////////////////////////////
#define CONFIG_VFLIP_ON		1


////////////////////////////
//Picasso Control Interface
////////////////////////////
#define CONFIG_PICASSO_CONTROL_ON		0
////////////////////////////
// 3D Function Support
////////////////////////////
#define CONFIG_3D_DISPLAY_SUPPORT_ON				0	// 0: Disable 3D function; 1: Enable 3D function
#define CONFIG_3D_LINE_ALTERNATIVE_ON				0	// 0: Enable 3D SG function; 1: Enable 3D PR function
#define CONFIG_3D_PR_OUTPUT_LR_SWAP					0	// 0: L first; 	1: R first
#define CONFIG_3D_SG_OUTPUT_120HZ_ON				0	// 0: 3D SG output 60Hz; 1: 3D SG output 120Hz
#define CONFIG_3D_SG_24HZ_OUTPUT_FHD_ON				0	// 3D SG output FHD when input is 24Hz 0: OFF(960x1080@120Hz); 1: ON(FHD@60Hz)
#define CONFIG_SCALER_2D_3D_CVT_HWSHIFT_ON			0	// 0: Enable 2Dcvt3D function; 1: Enable 2Dcvt3D function

/*
 * DCR Backlight range 091116 March , need tune by panel
 */
/*
#define PANEL_BACKLIGHT_MAX_DCR 100
#define PANEL_BACKLIGHT_MIN_DCR  0

#define FIX_LAST_LINE_ENABLE 0

//Toshiba
#define CCFL_BL_CHECK	0
#define BL_ON_OFF_ms	1000
#define BL_DUTY_MINIMUM	10
#define BL_DUTY_MIDDLE		70
#define BL_DUTY_MAXIMUM	100

#define DYNAMIC_DHTOTAL 1
*/

///////////////////////////
//Display port Settings
//////////////////////////
#define CONFIG_DISPLAY_PORT_CONFIG1     0
#define CONFIG_DISPLAY_PORT_CONFIG2     0

///////////////////////////
//SR Settings
//////////////////////////
#define CONFIG_SR_MODE                                          3                       //0:Hx2/Vx2, 1:Vx2, 2:Hx2, 3:SR_bypass
#define CONFIG_SR_PIXEL_MODE                            0                       //0:1 pixel, 1:2 pixel, 2:4 pixel

///////////////////////////
// SFG
///////////////////////////
#define CONFIG_SFG_SEG_NUM                              0
#define CONFIG_SFG_PORT_NUM                             0

#define CONFIG_PANEL_TYPE					0
#define CONFIG_PANEL_CUSTOM_INDEX			0

// #define BACKLIGHTLEVEL_NORMAL 100

///////////////////////////
// Panel Name
///////////////////////////
#define CONFIG_DISP_PANEL_NAME			"tsb_samsung_lsc400hm03.h"

