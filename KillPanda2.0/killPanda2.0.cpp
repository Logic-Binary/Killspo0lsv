#include <afx.h>
#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>
#include "md5.h"

CStringList repairFileList;
CStringList virusFileList;
PCHAR MD5Val;

//��������
VOID PrintProcessNameAndID(DWORD id) {
    TCHAR szProcessName[MAX_PATH] = _T("<unknow>");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    //�����ȡ����·��+����
    /*GetProcessImageFileName(hProcess, szProcessName, sizeof(szProcessName));
    _tprintf(_T("%s  (PID: %u)\n"), szProcessName, id);*/

    if (hProcess != NULL) {
        HMODULE hMod;
        DWORD cbNeeded;
        //ö��ģ��
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

//������������
void KillPanda() {
    DWORD pPid[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(pPid, sizeof(pPid), &cbNeeded)) {
        //ʧ�������˳�
        return;
    }
    //�����ж��ٽ���
    cProcesses = cbNeeded / 4;
    //ѭ������
    for (int i = 0; i < cProcesses; i++) {
        if (pPid[i] != 0) {
            PrintProcessNameAndID(pPid[i]);
        }
    }
}

// ---- md5ժҪ��ϣ ---- //   (�Ѿ�����)
void md5(char* data, int dataSize, CString& encodedHexStr)
{
    //MD5 md55;
    MD5 md55(data, dataSize);
    PBYTE buf = (PBYTE)md55.digest();
    //// ����md5��ϣ   
    //unsigned char mdStr[33] = { 0 };
    ////md55.((const uint32*)data, mdStr,dataSize);

    //// ��ϣ����ַ���   
    //// encodedStr = CString((const char*)mdStr);
    //// ��ϣ���ʮ�����ƴ� 32�ֽ�   
    //char buf[65] = { 0 };
    //char tmp[3] = { 0 };
    //for (int i = 0; i < 32; i++)
    //{
    //    sprintf_s(tmp, 3, "%02x", mdStr[i]);
    //    strcat_s(buf, 65, tmp);
    //}
    //buf[32] = '\0'; // ���涼��0����32�ֽڽض�   
    encodedHexStr = CString(buf);
}

//��ȡ��Ҫ�޸����ļ�����
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

//�Ƿ���Դ����
bool determineVirusAndDel(CFile& file, int fileSize, char* path) {

    DWORD type = needRepair(file.GetFileName());
    
    if (type != PE_FILE) {
        return false;
    }
    //file.Close();
    //��������˭������md5
    //0xD830ƫ��
    SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);
    HANDLE h = CreateFile(path,
        GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD err = GetLastError();

    //��ʧ���˳�
    if (h == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    DWORD size = GetFileSize(h, NULL);
    PCHAR buf = new char[size] {0};
    DWORD read = 0;
    ReadFile(h, (LPVOID)buf, size, &read, NULL);
    char Charabuf[33] = { 0 };

    //�ӱ���D830���ó�����
    memcpy(Charabuf, buf + 0xD830, 32);
    //printf(Charabuf);
    //system("pause");

    MD5 md555(Charabuf, 33);
    char* val = (char*)md555.digest();
    printf("·��%s:\n", path);
    printf("md5:%s\n", val);
    system("pause");

    //���md5��ͬ
    if (!memcmp(val, MD5Val, 32)) {
        system("pause");
        printf("·��%s\n:", path);
        DeleteFile(path);

        //�رվ��
        CloseHandle(h);
        //�ͷſռ�
        if (buf != NULL) {
            delete[] buf;
            buf = NULL;
        }

        return true;
    }


    //�رվ��
    CloseHandle(h);
    //�ͷſռ�
    if (buf != NULL) {
        delete[] buf;
        buf = NULL;
    }
    return false;
}

//�����ַ����Ƿ�ƥ��
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

//ɾ�������ͷŵ��ļ�(�Ѿ�����)
bool determineboshitAndDel(CFile& file, PTCHAR path) {
    //system("pause");
    const CHAR* needRepairPE[] = { _T("Desktop_.ini"), _T("autorun.inf") };
    for (size_t i = 0; i < 2; i++)
    {
        //printf("%s\n", file.GetFileName());
        if (file.GetFileName() == needRepairPE[i]) {
            //system("pause");
            file.Close();
            //�����ļ�����
            //CString path = file.GetFilePath();
            //printf("%s\n", path);

            DWORD err = SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);
            err = DeleteFile(path);
            err = GetLastError();
            //printf("%d", err);

            //CFile::Remove(file.GetFilePath());

            _tprintf(_T("[ �� ɾ�������ͷ��ļ�] "));
            return true;
        }
    }
    return false;
}

//�����ļ�
void traversePath(const TCHAR* dir) {

    TCHAR path[MAX_PATH] = { 0 };
    _stprintf_s(path, MAX_PATH, _T("%s\\*"), dir);

    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA findData = { 0 };
    hFind = FindFirstFile(path, &findData);
   
    if (hFind == INVALID_HANDLE_VALUE) {
        _tprintf(_T("[û���ļ�]\n"));
        return;
    }
    do {
        // ����ǵ�ǰĿ¼���ϲ�Ŀ¼,���ܼ����ݹ�.
        if (_tcscmp(findData.cFileName, _T(".")) == 0
            || _tcscmp(findData.cFileName, _T("..")) == 0)
        {
            continue;
        }
        _stprintf_s(path, MAX_PATH, _T("%s\\%s"),dir,findData.cFileName);
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // �ݹ����
            //printf("%s", path);
            //system("pause");
            //ƴ��·��(ʱ����ȣ�����д�ĺ��ʲ�)
            TCHAR temp1[MAX_PATH] = { 0 };
            strcat_s(temp1, MAX_PATH, path);
            strcat_s(temp1, MAX_PATH, "\\Desktop_.ini");
            //printf("ini·��:%s\n", temp1);
            SetFileAttributes(temp1, FILE_ATTRIBUTE_NORMAL);
            DeleteFile(temp1);
            TCHAR temp2[MAX_PATH] = { 0 };
            strcat_s(temp2, MAX_PATH, path);
            strcat_s(temp2, MAX_PATH, "\\autorun.inf");
            //printf("inf·��:%s\n", temp2);
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
            //����ļ�����10MB
            if (fileSize > 0xA00000)
                continue;
            else if (fileSize < 1)
                continue;
            //�ж��Ƿ��ǲ����³���ָ���ļ���ɾ��
            if (determineboshitAndDel(file, path)) {
                _tprintf(_T("%s\n"), path);
                continue;
            }
            //�޸��ļ�
            int fileType = needRepair(findData.cFileName);
            switch (fileType)
            {
            case PE_FILE: {
                //��ȡ���һ���ֽ�
                file.Seek(-1, CFile::end);                      //�Ӻ���ǰ��
                char lastBit;
                file.Read(&lastBit, 1);
                if (lastBit == 1) {
                    //��ȡ�ļ�β����
                    file.Seek(-MAX_PATH, CFile::end);           //�Ӻ���ǰ��260�ֽ�
                    char* fileEnd = new char[MAX_PATH] {0};
                    UINT readed = file.Read(fileEnd, MAX_PATH);
                    //�����ڼ���λ���ҵ���WhBoy
                    int signPos = rMemSearch(fileEnd, MAX_PATH, "WhBoy", 5);
                    if (signPos != -1) {
                        //�ҵ�WhBoy˵����ȷ����Ⱦ
                        int fileNamePos = signPos + 5;      //�ļ���λ��
                        //�ҵ�.��λ��
                        int number2Pos = rMemSearch(fileEnd, MAX_PATH, "\2", 1);
                        int sizePos = number2Pos + 1;
                        //��ȡ��С
                        int sourceFileSize = _ttoi(fileEnd + sizePos);
                        //��ȡ�ļ�
                        char* sourceFile = new char[fileSize] {0};
                        file.Seek(0, CFile::begin);
                        file.Read(sourceFile, fileSize);
                        //�ļ�ĩβ��ַ
                        char* end = sourceFile + fileSize;
                        //�����ļ�����
                        file.SetLength(sourceFileSize);
                        file.Seek(0, CFile::begin);
                        //д��Դ�ļ�
                        file.Write(((end - MAX_PATH) + signPos) - sourceFileSize - 1, sourceFileSize);
                        repairFileList.AddTail(file.GetFileName());
                        delete[] sourceFile;
                        _tprintf(_T("[*^*�޸�����Ⱦ�ļ�] "));
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
                    _tprintf(_T("[*^*�޸�WEB�ļ�] "));
                }
                delete[] fileBuff;
            }break;
            case NOPE: {
                _tprintf(_T("[^_^δ��Ⱦ�ļ�] "));
            }break;
            }
            //�ж��Ƿ񲡶���ֱ��ɱ��
            if (determineVirusAndDel(file, fileSize, path)) {
                _tprintf(_T("%s\n"), path);
                continue;
            }
            file.Close();
        }
        _tprintf(_T("%s\n"), path);
    } while (FindNextFile(hFind, &findData));
}

//�����̷�
void traverseAllDrives() {
    for (char a = 'C'; a <= 'Z'; a++) {
        UINT driveType = 0;
        CHAR rootPath[MAX_PATH] = { 0 };
        sprintf_s(rootPath, MAX_PATH, _T("%c:"), a);
        driveType = GetDriveType(rootPath);
        //printf("%s", rootPath);
        //system("pause");

        //ƴ��·��ɾ��Desktop_.ini
        TCHAR temp1[MAX_PATH] = { 0 };
        strcat_s(temp1, MAX_PATH, rootPath);
        strcat_s(temp1, MAX_PATH, "\\Desktop_.ini");
        SetFileAttributes(temp1, FILE_ATTRIBUTE_NORMAL);
        DeleteFile(temp1);

        //ƴ��һ��·��ɾ��autorun.inf
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


        if (driveType != DRIVE_NO_ROOT_DIR)                  // DRIVE_NO_ROOT_DIR: ·����Ч 
        {
            traversePath(rootPath);
        }
    }
    //��ӡ�޸��ļ���ɾ���ļ��б�
    CString fileName;
    POSITION rPos;
    rPos = virusFileList.GetHeadPosition();
    while (rPos != NULL)
    {
        fileName = virusFileList.GetNext(rPos);
        _tprintf(_T("ɾ�������ļ���%s\n"), fileName.GetBuffer());
    }
    rPos = repairFileList.GetHeadPosition();
    while (rPos != NULL)
    {
        fileName = repairFileList.GetNext(rPos);
        _tprintf(_T("�޸��ļ���%s\n"), fileName.GetBuffer());
    }
}

//ע����޸�
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

    //����ȡ�������md5
    MD5 md444("***��*��*��*��*��*Ⱦ*��*��*��***", 33);
    MD5Val = (char*)md444.digest();

    //�ȸɵ���������(��һ��)
    KillPanda();
    if (!delAutoRunAndProtect()) {
        printf("���ֶ�ɾ��ע���\n");
    }
    //�رս���(���ιر�)
    system("taskkill /im spo0lsv.exe /f");
    traverseAllDrives();
    printf("��ɱ���\n");
    system("pause");
    system("cls");
    printf("��������,���Ժ�.....");
    system("shutdown -r -t 10");
    system("pause");
    return 0;
}