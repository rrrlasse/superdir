Superdir is an alternative to the dir command on Windows.
![Superdir](https://github.com/rrrlasse/superdir/blob/main/superdir.png)
It shows alot more information:

```
Flags:
    -r: Recurse into sub directories
    -p: Show all permisssions
    -d: Show millisecond dates (will hide a few other columns)

    They can be combined like -rd or -rdp. You can also use slash (/) instead of dash (-)

Columns:
    Permissions
    -----------
    Without -p flag:
    Shows permissions for "Authenticated Users" and "Users" followed by any non-built-in users
    and groups

    With -p flag:
    Shows all permissions for all users and groups. Following are translated to short form:

    WD: Everyone      CO: Creator Owner  CG: Creator Group  DI: Dialup         NU: Network
    BT: Batch         IU: Interactive    SU: Service        AN: Anonymous      AU: Auth. Users
    RC: Restricted    WR: Write Restr.   SY: Local System   LS: Local Service  NS: Netw. Service
    BA: Admin         BU: Users          BG: Guests         PU: Power Users    BO: Account Ops
    SO: Server Ops    PO: Print Ops      BR: Backup Ops     RE: Replicators    RD: Remote Desktop
    NE: Netw. Config  AC: App Packages   TI: TrustInst.     WA: All Services   UD: UMDF Drivers

    File dates printed as relative time
    -----------------------------------
    Created
    Changed
    Accessed

    Size on disk
    ------------
    Can be less than 100% for sparse, compressed and offline files

    Attributes
    ----------
    A: ARCHIVE        S: SYSTEM               H: HIDDEN                 R: READONLY
    O: OFFLINE        I: NOT_CONTENT_INDEXED  C: COMPRESSED             V: INTEGRITY_STREAM
    X: NO_SCRUB_DATA  P: PINNED               U: UNPINNED               Q: SPARSE_FILE
    L: REPARSE_POINT  E: ENCRYPTED            M: RECALL_ON_DATA_ACCESS

    Last Write date
    ---------------

    Type
    ----
    <DIR> <SYM> <SYMD> <HARD> <JUNC>

    File size
    ---------

    Name
    ----
    This may be followed by a list of:
    Hardlink targets
    Alternate Data Streams
```

