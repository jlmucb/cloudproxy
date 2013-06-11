#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>

/*
 *  /proc/[pid]
 *  /proc/[pid]/stat
 */


// ---------------------------------------------------------------------------


bool uidfrompid(int pid, int* puid)
{
    char        szfileName[256];
    struct stat fattr;

    sprintf(szfileName, "/proc/%d/stat", pid);
    if((lstat(szfileName, &fattr))!=0) {
        printf("uidfrompid: stat failed\n");
        return false;
    } 
    *puid= fattr.st_uid;
    return true;
}


// ---------------------------------------------------------------------------


int main(int an, char** av)

{
    int             pid= getpid();
    int             uid= -1;
    struct passwd*  ppwd;

    printf("Uidfrompid, pid= %d\n", pid);

    if(!uidfrompid(pid, &uid)) {
        printf("uidfrompid failed\n");
        return 1;
    }
    printf("uid= %d\n", uid);

    ppwd= getpwuid(uid);
    if(ppwd==NULL) {
        printf("getpwdid failed\n");
        return 1;
    }
    printf("user %s has uid %d\n", ppwd->pw_name, uid);
    return 0;
}


// ---------------------------------------------------------------------------


