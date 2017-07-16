/*
	MD5 Bruteforcer is a CUDA based MD5 brute force program.
	Copyright (C) 2016-2017 Eric Kutcher

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "temperature.h"

#include <stdlib.h>

int GetGPUTemperature( NvPhysicalGpuHandle physical_gpu_handle )
{
	NV_GPU_THERMAL_SETTINGS set = { 0 };
	set.version = NV_GPU_THERMAL_SETTINGS_VER;
	set.count = 0;
	set.sensor[ 0 ].controller = NVAPI_THERMAL_CONTROLLER_UNKNOWN;
	set.sensor[ 0 ].target = NVAPI_THERMAL_TARGET_GPU;

	if ( NvAPI_GPU_GetThermalSettings( physical_gpu_handle, 0, &set ) != NVAPI_OK )
	{
		return -1;
	}

	return set.sensor[ 0 ].currentTemp;
}

NvPhysicalGpuHandle GetPhysicalGPUHandle()
{
	int i = 0;
	unsigned long count;
	NvDisplayHandle hDisplay_a[ NVAPI_MAX_PHYSICAL_GPUS * 2 ] = { 0 };
	NvPhysicalGpuHandle nvGPUHandle;

	if ( NvAPI_Initialize() != NVAPI_OK )
	{
		return NULL;
	}

	if ( NvAPI_EnumNvidiaDisplayHandle( i, &hDisplay_a[ i ] ) != NVAPI_OK )
	{
		return NULL;
	}

	if ( NvAPI_GetPhysicalGPUsFromDisplay( hDisplay_a[ 0 ], &nvGPUHandle, &count ) != NVAPI_OK )
	{
		return NULL;
	}

	return nvGPUHandle;
}
