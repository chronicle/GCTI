/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike__Resources__Template_Vbs_v3_3_to_v4_x
{
	meta:
		desc="Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		rs1 = "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
    author = "gssincla@google.com"
		
	strings:
	  $ea = "Excel.Application" nocase
    $vis = "Visible = False" nocase
    $wsc = "Wscript.Shell" nocase
    $regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
    $regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
    $regwrite = ".RegWrite" nocase
    $dw = "REG_DWORD"
    $code = ".CodeModule.AddFromString"
    $ao = "Auto_Open"
    $da = ".DisplayAlerts"

  condition:
    all of them
}