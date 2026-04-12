
export const ARTIFACT_PROFILES = {
  evtx: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.EventId',         label: 'EventID' },
      { key: 'raw.MapDescription',  label: 'Description' },
      { key: 'raw.SubjectUserName', label: 'Subject User' },
      { key: 'raw.TargetUserName',  label: 'Target User' },
      { key: 'raw.Computer',        label: 'Computer' },
      { key: 'raw.Channel',         label: 'Channel' },
      { key: 'raw.PayloadData1',    label: 'Payload 1' },
    ],
    hidden: [],
  },

  hayabusa: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.Level',           label: 'Level' },
      { key: 'raw.RuleTitle',       label: 'Rule' },
      { key: 'raw.Details',         label: 'Details' },
      { key: 'raw.Computer',        label: 'Computer' },
      { key: 'raw.MitreTactics',    label: 'MITRE Tactics' },
      { key: 'raw.Channel',         label: 'Channel' },
    ],
    hidden: [],
  },

  prefetch: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.ExecutableName',  label: 'Executable' },
      { key: 'raw.RunCount',        label: 'Run Count' },
      { key: 'raw.LastRun',         label: 'Last Run' },
      { key: 'raw.PreviousRun0',    label: 'Previous Run' },
      { key: 'raw.Hash',            label: 'Hash' },
    ],
    hidden: [],
  },

  mft: {
    priority: ['timestamp', 'source', 'description'],
    virtual: [
      { key: 'raw.FileName',        label: 'Filename' },
      { key: 'raw.ParentPath',      label: 'Parent Path' },
      { key: 'raw.FileSize',        label: 'Size' },
      { key: 'raw.Extension',       label: 'Extension' },
      { key: 'raw.Created0x10',     label: 'Created ($SI)' },
      { key: 'raw.Created0x30',     label: 'Created ($FN)' },
    ],
    hidden: [],
  },

  lnk: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.LocalPath',          label: 'Target Path' },
      { key: 'raw.TargetCreated',      label: 'Target Created' },
      { key: 'raw.TargetModified',     label: 'Target Modified' },
      { key: 'raw.MachineID',          label: 'Machine ID' },
      { key: 'raw.SourceFile',         label: 'LNK File' },
    ],
    hidden: [],
  },

  registry: {
    priority: ['timestamp', 'source', 'description'],
    virtual: [
      { key: 'raw.KeyPath',         label: 'Key Path' },
      { key: 'raw.ValueName',       label: 'Value Name' },
      { key: 'raw.ValueData',       label: 'Value Data' },
      { key: 'raw.HivePath',        label: 'Hive' },
      { key: 'raw.ValueType',       label: 'Type' },
    ],
    hidden: [],
  },

  amcache: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.FullPath',        label: 'Full Path' },
      { key: 'raw.SHA1',            label: 'SHA1' },
      { key: 'raw.ProgramName',     label: 'Program' },
      { key: 'raw.LinkDate',        label: 'Compile Date' },
      { key: 'raw.Publisher',       label: 'Publisher' },
    ],
    hidden: [],
  },

  appcompat: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.Path',                label: 'Path' },
      { key: 'raw.Executed',            label: 'Executed' },
      { key: 'raw.LastModifiedTimeUTC', label: 'Binary Modified' },
      { key: 'raw.CacheEntryPosition',  label: 'Cache Pos' },
    ],
    hidden: [],
  },

  shellbags: {
    priority: ['timestamp', 'source', 'description'],
    virtual: [
      { key: 'raw.AbsolutePath',    label: 'Path' },
      { key: 'raw.LastWriteTime',   label: 'Last Access' },
      { key: 'raw.ShellType',       label: 'Shell Type' },
      { key: 'raw.MruPosition',     label: 'MRU Pos' },
    ],
    hidden: [],
  },

  jumplist: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.LocalPath',          label: 'Target File' },
      { key: 'raw.AppIdDescription',   label: 'Application' },
      { key: 'raw.AppId',              label: 'App ID' },
      { key: 'raw.TargetCreated',      label: 'Target Created' },
      { key: 'raw.AccessCount',        label: 'Access Count' },
    ],
    hidden: [],
  },

  srum: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.ExeInfo',                 label: 'Application' },
      { key: 'raw.UserId',                  label: 'User SID' },
      { key: 'raw.ForegroundBytesRead',     label: 'FG Read' },
      { key: 'raw.ForegroundBytesWritten',  label: 'FG Written' },
      { key: 'raw.BackgroundBytesRead',     label: 'BG Read' },
      { key: 'raw.BackgroundBytesWritten',  label: 'BG Written' },
    ],
    hidden: [],
  },

  wxtcmd: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.DisplayText',     label: 'Display Text' },
      { key: 'raw.ActivityType',    label: 'Activity' },
      { key: 'raw.StartTime',       label: 'Start Time' },
      { key: 'raw.EndTime',         label: 'End Time' },
      { key: 'raw.AppId',           label: 'App ID' },
    ],
    hidden: [],
  },

  recycle: {
    priority: ['timestamp', 'source', 'description'],
    virtual: [
      { key: 'raw.FileName',        label: 'Original Name' },
      { key: 'raw.DeletedOn',       label: 'Deleted On' },
      { key: 'raw.FileSize',        label: 'Size' },
      { key: 'raw.SourceName',      label: 'Original Path' },
    ],
    hidden: [],
  },

  bits: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.JobName',         label: 'Job Name' },
      { key: 'raw.Files',           label: 'Files / URLs' },
      { key: 'raw.CreationTime',    label: 'Created' },
      { key: 'raw.CompletedTime',   label: 'Completed' },
      { key: 'raw.LocalPath',       label: 'Local Path' },
    ],
    hidden: [],
  },

  sum: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.UserName',                label: 'User' },
      { key: 'raw.ClientName',              label: 'Client Machine' },
      { key: 'raw.AuthenticatedUserName',   label: 'Auth User' },
      { key: 'raw.InsertDate',              label: 'First Seen' },
      { key: 'raw.LastAccess',              label: 'Last Access' },
    ],
    hidden: [],
  },

  sqle: {
    priority: ['timestamp', 'description', 'source'],
    virtual: [
      { key: 'raw.URL',             label: 'URL' },
      { key: 'raw.Title',           label: 'Page Title' },
      { key: 'raw.LastVisitDate',   label: 'Last Visit' },
      { key: 'raw.VisitCount',      label: 'Visit Count' },
      { key: 'raw.Profile',         label: 'Profile' },
    ],
    hidden: [],
  },
};

export const ARTIFACT_ALL_FIELDS = {
  evtx: [
    { key: 'raw.EventId',         label: 'EventID' },
    { key: 'raw.MapDescription',  label: 'Description' },
    { key: 'raw.SubjectUserName', label: 'Subject User' },
    { key: 'raw.TargetUserName',  label: 'Target User' },
    { key: 'raw.Computer',        label: 'Computer' },
    { key: 'raw.Channel',         label: 'Channel' },
    { key: 'raw.PayloadData1',    label: 'Payload 1' },
    { key: 'raw.PayloadData2',    label: 'Payload 2' },
    { key: 'raw.PayloadData3',    label: 'Payload 3' },
    { key: 'raw.PayloadData4',    label: 'Payload 4' },
    { key: 'raw.ProcessId',       label: 'PID' },
    { key: 'raw.RemoteHost',      label: 'Remote Host' },
    { key: 'raw.UserName',        label: 'User' },
    { key: 'raw.ExecutableInfo',  label: 'Executable' },
    { key: 'raw.HiddenRecord',    label: 'Hidden Record' },
  ],

  hayabusa: [
    { key: 'raw.Level',           label: 'Level' },
    { key: 'raw.RuleTitle',       label: 'Rule' },
    { key: 'raw.Details',         label: 'Details' },
    { key: 'raw.Computer',        label: 'Computer' },
    { key: 'raw.MitreTactics',    label: 'MITRE Tactics' },
    { key: 'raw.Channel',         label: 'Channel' },
    { key: 'raw.MitreTechniques', label: 'MITRE Techniques' },
    { key: 'raw.EventID',         label: 'EventID' },
    { key: 'raw.RecordID',        label: 'Record ID' },
  ],

  prefetch: [
    { key: 'raw.ExecutableName',  label: 'Executable' },
    { key: 'raw.RunCount',        label: 'Run Count' },
    { key: 'raw.LastRun',         label: 'Last Run' },
    { key: 'raw.PreviousRun0',    label: 'Previous Run' },
    { key: 'raw.Hash',            label: 'Hash' },
    { key: 'raw.PreviousRun1',    label: 'Run -2' },
    { key: 'raw.PreviousRun2',    label: 'Run -3' },
    { key: 'raw.PreviousRun3',    label: 'Run -4' },
    { key: 'raw.PreviousRun4',    label: 'Run -5' },
    { key: 'raw.PreviousRun5',    label: 'Run -6' },
    { key: 'raw.PreviousRun6',    label: 'Run -7' },
    { key: 'raw.SourceAccessed',  label: 'File Accessed' },
    { key: 'raw.Size',            label: 'Size' },
  ],

  mft: [
    { key: 'raw.FileName',           label: 'Filename' },
    { key: 'raw.ParentPath',         label: 'Parent Path' },
    { key: 'raw.FileSize',           label: 'Size' },
    { key: 'raw.Extension',          label: 'Extension' },
    { key: 'raw.Created0x10',        label: 'Created ($SI)' },
    { key: 'raw.Created0x30',        label: 'Created ($FN)' },
    { key: 'raw.LastModified0x10',   label: 'Modified ($SI)' },
    { key: 'raw.LastModified0x30',   label: 'Modified ($FN)' },
    { key: 'raw.LastAccess0x10',     label: 'Last Access' },
    { key: 'raw.EntryNumber',        label: 'Entry #' },
    { key: 'raw.IsDirectory',        label: 'Is Directory' },
    { key: 'raw.InUse',              label: 'In Use' },
    { key: 'raw.HasAds',             label: 'Has ADS' },
    { key: 'raw.SI_FN_Shift',        label: 'SI/FN Shift' },
    { key: 'raw.ZoneIdContents',     label: 'Zone ID' },
  ],

  lnk: [
    { key: 'raw.LocalPath',          label: 'Target Path' },
    { key: 'raw.TargetCreated',      label: 'Target Created' },
    { key: 'raw.TargetModified',     label: 'Target Modified' },
    { key: 'raw.MachineID',          label: 'Machine ID' },
    { key: 'raw.SourceFile',         label: 'LNK File' },
    { key: 'raw.TargetAccessed',     label: 'Target Accessed' },
    { key: 'raw.WorkingDirectory',   label: 'Working Dir' },
    { key: 'raw.Arguments',          label: 'Arguments' },
    { key: 'raw.MachineMACAddress',  label: 'MAC Address' },
    { key: 'raw.FileSize',           label: 'Target Size' },
    { key: 'raw.SourceCreated',      label: 'LNK Created' },
    { key: 'raw.SourceModified',     label: 'LNK Modified' },
  ],

  registry: [
    { key: 'raw.KeyPath',            label: 'Key Path' },
    { key: 'raw.ValueName',          label: 'Value Name' },
    { key: 'raw.ValueData',          label: 'Value Data' },
    { key: 'raw.HivePath',           label: 'Hive' },
    { key: 'raw.ValueType',          label: 'Type' },
    { key: 'raw.ValueData2',         label: 'Value Data 2' },
    { key: 'raw.UserName',           label: 'User' },
    { key: 'raw.Description',        label: 'Description' },
    { key: 'raw.Category',           label: 'Category' },
    { key: 'raw.Comment',            label: 'Comment' },
    { key: 'raw.DeletedRecord',      label: 'Deleted' },
  ],

  amcache: [
    { key: 'raw.FullPath',                    label: 'Full Path' },
    { key: 'raw.SHA1',                        label: 'SHA1' },
    { key: 'raw.ProgramName',                 label: 'Program' },
    { key: 'raw.LinkDate',                    label: 'Compile Date' },
    { key: 'raw.Publisher',                   label: 'Publisher' },
    { key: 'raw.FileKeyLastWriteTimestamp',   label: 'First Seen' },
    { key: 'raw.ProductName',                 label: 'Product' },
    { key: 'raw.FileVersion',                 label: 'Version' },
    { key: 'raw.ProductVersion',              label: 'Product Version' },
    { key: 'raw.FileDescription',             label: 'Description' },
    { key: 'raw.FileType',                    label: 'File Type' },
    { key: 'raw.FileSize',                    label: 'Size' },
  ],

  appcompat: [
    { key: 'raw.Path',                label: 'Path' },
    { key: 'raw.Executed',            label: 'Executed' },
    { key: 'raw.LastModifiedTimeUTC', label: 'Binary Modified' },
    { key: 'raw.CacheEntryPosition',  label: 'Cache Pos' },
    { key: 'raw.ControlSet',          label: 'Control Set' },
    { key: 'raw.Duplicate',           label: 'Duplicate' },
  ],

  shellbags: [
    { key: 'raw.AbsolutePath',    label: 'Path' },
    { key: 'raw.LastWriteTime',   label: 'Last Access' },
    { key: 'raw.ShellType',       label: 'Shell Type' },
    { key: 'raw.MruPosition',     label: 'MRU Pos' },
    { key: 'raw.Extension',       label: 'Extension' },
    { key: 'raw.CreatedOn',       label: 'Created On' },
    { key: 'raw.ModifiedOn',      label: 'Modified On' },
    { key: 'raw.AccessedOn',      label: 'Accessed On' },
    { key: 'raw.Value',           label: 'Value' },
  ],

  jumplist: [
    { key: 'raw.LocalPath',          label: 'Target File' },
    { key: 'raw.AppIdDescription',   label: 'Application' },
    { key: 'raw.AppId',              label: 'App ID' },
    { key: 'raw.TargetCreated',      label: 'Target Created' },
    { key: 'raw.AccessCount',        label: 'Access Count' },
    { key: 'raw.TargetModified',     label: 'Target Modified' },
    { key: 'raw.SourceFile',         label: 'JumpList File' },
    { key: 'raw.WorkingDirectory',   label: 'Working Dir' },
    { key: 'raw.Arguments',          label: 'Arguments' },
    { key: 'raw.MachineID',          label: 'Machine ID' },
    { key: 'raw.MachineMACAddress',  label: 'MAC Address' },
    { key: 'raw.FileSize',           label: 'File Size' },
    { key: 'raw.PinStatus',          label: 'Pinned' },
  ],

  srum: [
    { key: 'raw.ExeInfo',                 label: 'Application' },
    { key: 'raw.UserId',                  label: 'User SID' },
    { key: 'raw.ForegroundBytesRead',     label: 'FG Read' },
    { key: 'raw.ForegroundBytesWritten',  label: 'FG Written' },
    { key: 'raw.BackgroundBytesRead',     label: 'BG Read' },
    { key: 'raw.BackgroundBytesWritten',  label: 'BG Written' },
    { key: 'raw.AppId',                   label: 'App ID' },
    { key: 'raw.SidType',                 label: 'SID Type' },
    { key: 'raw.ConnectStartTime',        label: 'Connect Start' },
    { key: 'raw.InterfaceLuid',           label: 'Interface LUID' },
  ],

  wxtcmd: [
    { key: 'raw.DisplayText',     label: 'Display Text' },
    { key: 'raw.ActivityType',    label: 'Activity' },
    { key: 'raw.StartTime',       label: 'Start Time' },
    { key: 'raw.EndTime',         label: 'End Time' },
    { key: 'raw.AppId',           label: 'App ID' },
    { key: 'raw.Sid',             label: 'User SID' },
    { key: 'raw.LastModifiedTime',label: 'Last Modified' },
    { key: 'raw.Description',     label: 'Description' },
    { key: 'raw.Duration',        label: 'Duration' },
    { key: 'raw.Platform',        label: 'Platform' },
  ],

  recycle: [
    { key: 'raw.FileName',        label: 'Original Name' },
    { key: 'raw.DeletedOn',       label: 'Deleted On' },
    { key: 'raw.FileSize',        label: 'Size' },
    { key: 'raw.SourceName',      label: 'Original Path' },
    { key: 'raw.FileType',        label: 'File Type' },
  ],

  bits: [
    { key: 'raw.JobName',         label: 'Job Name' },
    { key: 'raw.Files',           label: 'Files / URLs' },
    { key: 'raw.CreationTime',    label: 'Created' },
    { key: 'raw.CompletedTime',   label: 'Completed' },
    { key: 'raw.LocalPath',       label: 'Local Path' },
    { key: 'raw.OwnerSID',        label: 'Owner SID' },
    { key: 'raw.TransferId',      label: 'Transfer ID' },
    { key: 'raw.ModifiedTime',    label: 'Modified' },
    { key: 'raw.DownloadType',    label: 'Download Type' },
    { key: 'raw.ErrorCode',       label: 'Error Code' },
  ],

  sum: [
    { key: 'raw.UserName',                label: 'User' },
    { key: 'raw.ClientName',              label: 'Client Machine' },
    { key: 'raw.AuthenticatedUserName',   label: 'Auth User' },
    { key: 'raw.InsertDate',              label: 'First Seen' },
    { key: 'raw.LastAccess',              label: 'Last Access' },
    { key: 'raw.RoleGuid',                label: 'Role GUID' },
    { key: 'raw.ComputerName',            label: 'Server' },
    { key: 'raw.TotalAccesses',           label: 'Total Accesses' },
  ],

  sqle: [
    { key: 'raw.URL',             label: 'URL' },
    { key: 'raw.Title',           label: 'Page Title' },
    { key: 'raw.LastVisitDate',   label: 'Last Visit' },
    { key: 'raw.VisitCount',      label: 'Visit Count' },
    { key: 'raw.Profile',         label: 'Profile' },
    { key: 'raw.SourceType',      label: 'Browser' },
    { key: 'raw.VisitDate',       label: 'First Visit' },
    { key: 'raw.TypedCount',      label: 'Typed Count' },
    { key: 'raw.Hidden',          label: 'Hidden' },
  ],
};

export function getProfileForArtifact(artifactType) {
  return ARTIFACT_PROFILES[artifactType] || null;
}
