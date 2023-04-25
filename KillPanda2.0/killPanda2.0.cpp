#include <afx.h>
#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>
#include "md5.h"

CStringList repairFileList;
CStringList virusFileList;
PCHAR MD5Val;

//遍历进程
VOID PrintProcessNameAndID(DWORD id) {
    TCHAR szProcessName[MAX_PATH] = _T("<unknow>");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    //这个获取的是路径+名称
    /*GetProcessImageFileName(hProcess, szProcessName, sizeof(szProcessName));
    _tprintf(_T("%s  (PID: %u)\n"), szProcessName, id);*/

    if (hProcess != NULL) {
        HMODULE hMod;
        DWORD cbNeeded;
        //枚举模块
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
        }
    }
    //_tprintf(_T("%s  (PID: %u)\n"), szProcessName, id);
    if (!strcmp(szProcessName, "spo0lsv.exe")) {

        int err_t = TerminateProcess(hProcess, NULL);
        err_t = GetLastError();
        /*printf("%d", err_t);
        system("pause");*/
    }

    CloseHandle(hProcess);

}

//结束病毒进程
void KillPanda() {
    DWORD pPid[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(pPid, sizeof(pPid), &cbNeeded)) {
        //失败了则退出
        return;
    }
    //计算有多少进程
    cProcesses = cbNeeded / 4;
    //循环遍历
    for (int i = 0; i < cProcesses; i++) {
        if (pPid[i] != 0) {
            PrintProcessNameAndID(pPid[i]);
        }
    }
}

// ---- md5摘要哈希 ---- //   (已经废弃)
void md5(char* data, int dataSize, CString& encodedHexStr)
{
    //MD5 md55;
    MD5 md55(data, dataSize);
    PBYTE buf = (PBYTE)md55.digest();
    //// 调用md5哈希   
    //unsigned char mdStr[33] = { 0 };
    ////md55.((const uint32*)data, mdStr,dataSize);

    //// 哈希后的字符串   
    //// encodedStr = CString((const char*)mdStr);
    //// 哈希后的十六进制串 32字节   
    //char buf[65] = { 0 };
    //char tmp[3] = { 0 };
    //for (int i = 0; i < 32; i++)
    //{
    //    sprintf_s(tmp, 3, "%02x", mdStr[i]);
    //    strcat_s(buf, 65, tmp);
    //}
    //buf[32] = '\0'; // 后面都是0，从32字节截断   
    encodedHexStr = CString(buf);
}

//获取需要修复的文件类型
int needRepair(CString filename) {
    const CHAR* needRepairPE[] = { _T("EXE"), _T("SCR"), _T("PIF"), _T("COM") };
    const CHAR* needRepairWEB[] = { _T("HTM"),_T("HTML"),_T("PHP"),_T("JSP"),_T("ASPX") };

    int pos = filename.ReverseFind(L'.');
    CString type = filename.Mid(pos + 1, filename.GetLength() - pos - 1);
    type = type.MakeUpper();
    for (size_t i = 0; i < _countof(needRepairPE); i++)
    {
        if (type == needRepairPE[i])
            return PE_FILE;
        else if (type == needRepairWEB[i])
            return WEB_FILE;
    }
    if (type == needRepairWEB[4])
        return WEB_FILE;

    return NOPE;
}

//是否是源病毒
bool determineVirusAndDel(CFile& file, int fileSize, char* path) {

    DWORD type = needRepair(file.GetFileName());
    
    if (type != PE_FILE) {
        return false;
    }
    //file.Close();
    //不管他是谁，先求md5
    //0xD830偏移
    SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);
    HANDLE h = CreateFile(path,
        GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD err = GetLastError();

    //打开失败退出
    if (h == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    DWORD size = GetFileSize(h, NULL);
    PCHAR buf = new char[size] {0};
    DWORD read = 0;
    ReadFile(h, (LPVOID)buf, size, &read, NULL);
    char Charabuf[33] = { 0 };

    //从便宜D830处拿出内容
    memcpy(Charabuf, buf + 0xD830, 32);
    //printf(Charabuf);
    //system("pause");

    MD5 md555(Charabuf, 33);
    char* val = (char*)md555.digest();
    printf("路径%s:\n", path);
    printf("md5:%s\n", val);
    system("pause");

    //如果md5相同
    if (!memcmp(val, MD5Val, 32)) {
        system("pause");
        printf("路径%s\n:", path);
        DeleteFile(path);

        //关闭句柄
        CloseHandle(h);
        //释放空间
        if (buf != NULL) {
            delete[] buf;
            buf = NULL;
        }

        return true;
    }


    //关闭句柄
    CloseHandle(h);
    //释放空间
    if (buf != NULL) {
        delete[] buf;
        buf = NULL;
    }
    return false;
}

//查找字符串是否匹配
int rMemSearch(char* buff, int buffSize, const char* str, int strSize) {
    for (size_t i = buffSize; i > 0; i--)
    {
        char* findBuff = buff + i;
        if (!memcmp(findBuff, str, strSize)) {
            return i;
        }
    }
    return -1;
}

//删除病毒释放的文件(已经废弃)
bool determineboshitAndDel(CFile& file, PTCHAR path) {
    //system("pause");
    const CHAR* needRepairPE[] = { _T("Desktop_.ini"), _T("autorun.inf") };
    for (size_t i = 0; i < 2; i++)
    {
        //printf("%s\n", file.GetFileName());
        if (file.GetFileName() == needRepairPE[i]) {
            //system("pause");
            file.Close();
            //设置文件属性
            //CString path = file.GetFilePath();
            //printf("%s\n", path);

            DWORD err = SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);
            err = DeleteFile(path);
            err = GetLastError();
            //printf("%d", err);

            //CFile::Remove(file.GetFilePath());

            _tprintf(_T("[ × 删除病毒释放文件] "));
            return true;
        }
    }
    return false;
}

//遍历文件
void traversePath(const TCHAR* dir) {

    TCHAR path[MAX_PATH] = { 0 };
    _stprintf_s(path, MAX_PATH, _T("%s\\*"), dir);

    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA findData = { 0 };
    hFind = FindFirstFile(path, &findData);
   
    if (hFind == INVALID_HANDLE_VALUE) {
        _tprintf(_T("[没有文件]\n"));
        return;
    }
    do {
        // 如果是当前目录和上层目录,不能继续递归.
        if (_tcscmp(findData.cFileName, _T(".")) == 0
            || _tcscmp(findData.cFileName, _T("..")) == 0)
        {
            continue;
        }
        _stprintf_s(path, MAX_PATH, _T("%s\\%s"),dir,findData.cFileName);
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // 递归遍历
            //printf("%s", path);
            //system("pause");
            //拼接路径(时间紧迫，这里写的很潦草)
            TCHAR temp1[MAX_PATH] = { 0 };
            strcat_s(temp1, MAX_PATH, path);
            strcat_s(temp1, MAX_PATH, "\\Desktop_.ini");
            //printf("ini路径:%s\n", temp1);
            SetFileAttributes(temp1, FILE_ATTRIBUTE_NORMAL);
            DeleteFile(temp1);
            TCHAR temp2[MAX_PATH] = { 0 };
            strcat_s(temp2, MAX_PATH, path);
            strcat_s(temp2, MAX_PATH, "\\autorun.inf");
            //printf("inf路径:%s\n", temp2);
            SetFileAttributes(temp2, FILE_ATTRIBUTE_NORMAL);
            DeleteFile(temp2);
            //system("pause");
            traversePath(path);
        }
        else {
            CFile file;
            if (!file.Open(path, CFile::modeReadWrite))
                continue;
            DWORD fileSize = file.GetLength();
            //如果文件大于10MB
            if (fileSize > 0xA00000)
                continue;
            else if (fileSize < 1)
                continue;
            //判断是否是病毒吐出的指定文件并删除
            if (determineboshitAndDel(file, path)) {
                _tprintf(_T("%s\n"), path);
                continue;
            }
            //修复文件
            int fileType = needRepair(findData.cFileName);
            switch (fileType)
            {
            case PE_FILE: {
                //读取最后一个字节
                file.Seek(-1, CFile::end);                      //从后往前读
                char lastBit;
                file.Read(&lastBit, 1);
                if (lastBit == 1) {
                    //读取文件尾内容
                    file.Seek(-MAX_PATH, CFile::end);           //从后往前读260字节
                    char* fileEnd = new char[MAX_PATH] {0};
                    UINT readed = file.Read(fileEnd, MAX_PATH);
                    //倒数第几个位置找到了WhBoy
                    int signPos = rMemSearch(fileEnd, MAX_PATH, "WhBoy", 5);
                    if (signPos != -1) {
                        //找到WhBoy说明的确被感染
                        int fileNamePos = signPos + 5;      //文件名位置
                        //找到.的位置
                        int number2Pos = rMemSearch(fileEnd, MAX_PATH, "\2", 1);
                        int sizePos = number2Pos + 1;
                        //获取大小
                        int sourceFileSize = _ttoi(fileEnd + sizePos);
                        //获取文件
                        char* sourceFile = new char[fileSize] {0};
                        file.Seek(0, CFile::begin);
                        file.Read(sourceFile, fileSize);
                        //文件末尾地址
                        char* end = sourceFile + fileSize;
                        //更改文件长度
                        file.SetLength(sourceFileSize);
                        file.Seek(0, CFile::begin);
                        //写入源文件
                        file.Write(((end - MAX_PATH) + signPos) - sourceFileSize - 1, sourceFileSize);
                        repairFileList.AddTail(file.GetFileName());
                        delete[] sourceFile;
                        _tprintf(_T("[*^*修复被感染文件] "));
                    }
                    delete[] fileEnd;
                }
            }break;
            case WEB_FILE: {
                char* fileBuff = new char[fileSize];
                file.Seek(0, CFile::begin);
                file.Read(fileBuff, fileSize);
                char iframe[] = { _T("<iframe src=http://www.ac86.cn/66/index.htm width=\"0\" height=\"0\"></iframe>") };
                int iframeSize = _countof(iframe) - 1;
                int pos = rMemSearch(fileBuff, fileSize, iframe, iframeSize);
                if (pos != -1) {
                    file.Write(fileBuff, pos);
                    file.SetLength(pos);
                    _tprintf(_T("[*^*修复WEB文件] "));
                }
                delete[] fileBuff;
            }break;
            case NOPE: {
                _tprintf(_T("[^_^未感染文件] "));
            }break;
            }
            //判断是否病毒并直接杀掉
            if (determineVirusAndDel(file, fileSize, path)) {
                _tprintf(_T("%s\n"), path);
                continue;
            }
            file.Close();
        }
        _tprintf(_T("%s\n"), path);
    } while (FindNextFile(hFind, &findData));
}

//遍历盘符
void traverseAllDrives() {
    for (char a = 'C'; a <= 'Z'; a++) {
        UINT driveType = 0;
        CHAR rootPath[MAX_PATH] = { 0 };
        sprintf_s(rootPath, MAX_PATH, _T("%c:"), a);
        driveType = GetDriveType(rootPath);
        //printf("%s", rootPath);
        //system("pause");

        //拼接路径删除Desktop_.ini
        TCHAR temp1[MAX_PATH] = { 0 };
        strcat_s(temp1, MAX_PATH, rootPath);
        strcat_s(temp1, MAX_PATH, "\\Desktop_.ini");
        SetFileAttributes(temp1, FILE_ATTRIBUTE_NORMAL);
        DeleteFile(temp1);

        //拼接一下路径删除autorun.inf
        TCHAR temp2[MAX_PATH] = { 0 };
        strcat_s(temp2, MAX_PATH, "\\autorun.inf");
        int err = SetFileAttributes(temp2, FILE_ATTRIBUTE_NORMAL);
        err = GetLastError();
        DeleteFile(temp2);
        err = GetLastError();

        TCHAR temp3[MAX_PATH] = { 0 };
        strcat_s(temp3, MAX_PATH, rootPath);
        strcat_s(temp3, MAX_PATH, "\\setup.exe");
        SetFileAttributes(temp3, FILE_ATTRIBUTE_NORMAL);
        DeleteFile(temp3);

        SetFileAttributes("C:\\Windows\\System32\\drivers\\spo0lsv.exe", FILE_ATTRIBUTE_NORMAL);
        DeleteFile("C:\\Windows\\System32\\drivers\\spo0lsv.exe");
        SetFileAttributes("D:\\autorun.inf", FILE_ATTRIBUTE_NORMAL);
        DeleteFile("D:\\autorun.inf");


        if (driveType != DRIVE_NO_ROOT_DIR)                  // DRIVE_NO_ROOT_DIR: 路径无效 
        {
            traversePath(rootPath);
        }
    }
    //打印修复文件和删除文件列表
    CString fileName;
    POSITION rPos;
    rPos = virusFileList.GetHeadPosition();
    while (rPos != NULL)
    {
        fileName = virusFileList.GetNext(rPos);
        _tprintf(_T("删除病毒文件：%s\n"), fileName.GetBuffer());
    }
    rPos = repairFileList.GetHeadPosition();
    while (rPos != NULL)
    {
        fileName = repairFileList.GetNext(rPos);
        _tprintf(_T("修复文件：%s\n"), fileName.GetBuffer());
    }
}

//注册表修复
bool delAutoRunAndProtect() {
    HKEY hKey;
    bool result = true;
    if (RegOpenKey(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS)
    {
        RegDeleteValue(hKey, "svcshare");
        RegCloseKey(hKey);
    }
    else result = false;
    if (RegOpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL", &hKey) == ERROR_SUCCESS)
    {
        int value = 1;
        RegSetKeyValue(hKey, "CheckedValue", 0, REG_DWORD, &value, 4);
        RegCloseKey(hKey);
    }
    else result = false;
    return result;
}

int main()
{
    system("mode con cols=130 lines=50");

    //先提取特征算出md5
    MD5 md444("***武*汉*男*生*感*染*下*载*者***", 33);
    MD5Val = (char*)md444.digest();

    //先干掉病毒进程(第一次)
    KillPanda();
    if (!delAutoRunAndProtect()) {
        printf("请手动删除注册表\n");
    }
    //关闭进程(二次关闭)
    system("taskkill /im spo0lsv.exe /f");
    traverseAllDrives();
    printf("查杀完成\n");
    system("pause");
    system("cls");
    printf("即将重启,请稍后.....");
    system("shutdown -r -t 10");
    system("pause");
    return 0;
}