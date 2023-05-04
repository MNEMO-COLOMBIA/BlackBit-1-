rule blackbit_ransomware
{
    meta:
        author = "Fevar54"
        description = "Detects BlackBit ransomware behavior"
        Fuente: "https://blog.cyble.com/2023/05/03/blackbit-ransomware-a-threat-from-the-shadows-of-lokilocker/" 
        
    strings:
        $persian = "fa-IR"
        $mutex_name = "BlackBitMutex"
        $startup_path1 = "*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\winlogon.exe"
        $startup_path2 = "C:\\ProgramData\\winlogon.exe"
        $encrypted_file_extension = ".blackbit"
    
    condition:
        $persian and !($persian in any of them) and 
        mutex($mutex_name) and 
        (
            $startup_path1 or
            $startup_path2
        ) and 
        any of them
        for any file_extension in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt"}
}
