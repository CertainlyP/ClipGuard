// =========================================================================
// ClipGuard — Clipboard Provenance Detection for ClickFix Defense
// =========================================================================
//
// .csproj:
//   <TargetFramework>net8.0-windows</TargetFramework>
//   <UseWindowsForms>true</UseWindowsForms>
//   <OutputType>WinExe</OutputType>
//   <Nullable>disable</Nullable>
//
// Run as Administrator.
// =========================================================================

using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

using WinApp = System.Windows.Forms.Application;

namespace ClipGuard
{
    #region Native Win32 API

    static class NativeMethods
    {
        [DllImport("user32.dll")]
        public static extern IntPtr GetClipboardOwner();

        [DllImport("user32.dll")]
        public static extern uint GetClipboardSequenceNumber();

        [DllImport("user32.dll")]
        public static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll")]
        public static extern bool CloseClipboard();

        [DllImport("user32.dll")]
        public static extern bool IsClipboardFormatAvailable(uint format);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern uint RegisterClipboardFormatW(string lpszFormat);

        [DllImport("user32.dll")]
        public static extern IntPtr GetClipboardData(uint uFormat);

        [DllImport("user32.dll")]
        public static extern bool AddClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetClassNameW(IntPtr hWnd, StringBuilder buf, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after,
            string className, string windowName);

        [DllImport("user32.dll")]
        public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn,
            IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll")]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(int vKey);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        [DllImport("user32.dll")]
        public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        public const int WH_KEYBOARD_LL = 13;
        public const int WM_KEYDOWN = 0x0100;
        public const int WM_CLIPBOARDUPDATE = 0x031D;
        public const int VK_V = 0x56;
        public const int VK_CONTROL = 0x11;
        public const int VK_SHIFT = 0x10;
        public const int VK_MENU = 0x12;
        public const uint CF_UNICODETEXT = 13;
        public const uint INPUT_KEYBOARD = 1;
        public const uint KEYEVENTF_KEYUP = 0x0002;

        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        public struct KBDLLHOOKSTRUCT
        {
            public uint vkCode, scanCode, flags, time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct INPUT
        {
            public uint type;
            public INPUTUNION u;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct INPUTUNION
        {
            [FieldOffset(0)] public KEYBDINPUT ki;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEYBDINPUT
        {
            public ushort wVk, wScan;
            public uint dwFlags, time;
            public IntPtr dwExtraInfo;
        }
    }

    #endregion

    #region Clipboard State

    class ClipboardState
    {
        public uint Sequence;
        public uint SourcePid;
        public string SourceProcess = "";
        public bool IsBrowser;
        public bool HasHtmlFormat;
        public bool IsTextOnly;
        public int ContentLength;
        public string ContentPreview = "";
        public DateTime Timestamp;
    }

    #endregion

    #region Config

    static class Config
    {
        public static readonly string[] Browsers = {
            "msedge", "chrome", "firefox", "brave",
            "opera", "vivaldi", "chromium", "arc"
        };

        public static readonly string[] ExecSurfaces = {
            "cmd", "powershell", "pwsh", "windowsterminal", "wt"
        };

        public const int MinContentLength = 15;
        public const int PreviewMaxChars = 200;
        public static bool StrictMode = false;
    }

    #endregion

    #region Logger

    static class Logger
    {
        private static readonly string _logFilePath;

        static Logger()
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ClipGuard");
            Directory.CreateDirectory(dir);
            _logFilePath = Path.Combine(dir, "shield.log");
        }

        public static void Log(string msg)
        {
            try
            {
                File.AppendAllText(_logFilePath,
                    $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {msg}{Environment.NewLine}");
            }
            catch { }
        }

        public static string LogFilePath => _logFilePath;
    }

    #endregion

    #region Clipboard Listener

    class ClipboardListener : NativeWindow
    {
        private static readonly uint CF_HTML =
            NativeMethods.RegisterClipboardFormatW("HTML Format");

        public ClipboardState CurrentState { get; private set; } = new ClipboardState();

        public ClipboardListener()
        {
            CreateHandle(new CreateParams());
            NativeMethods.AddClipboardFormatListener(Handle);
            Logger.Log("Clipboard listener active.");
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == NativeMethods.WM_CLIPBOARDUPDATE)
            {
                Snapshot();
                m.Result = IntPtr.Zero;
                return;
            }
            base.WndProc(ref m);
        }

        private void Snapshot()
        {
            var s = new ClipboardState
            {
                Timestamp = DateTime.UtcNow,
                Sequence = NativeMethods.GetClipboardSequenceNumber()
            };

            IntPtr owner = NativeMethods.GetClipboardOwner();
            if (owner == IntPtr.Zero)
            {
                Thread.Sleep(10);
                owner = NativeMethods.GetClipboardOwner();
            }

            if (owner != IntPtr.Zero)
            {
                uint pid;
                NativeMethods.GetWindowThreadProcessId(owner, out pid);
                s.SourcePid = pid;
                try
                {
                    using (var p = Process.GetProcessById((int)pid))
                        s.SourceProcess = p.ProcessName.ToLowerInvariant();
                }
                catch { s.SourceProcess = "unknown"; }
            }
            else
            {
                s.SourceProcess = "unknown";
            }

            foreach (var b in Config.Browsers)
            {
                if (s.SourceProcess.Equals(b, StringComparison.OrdinalIgnoreCase))
                {
                    s.IsBrowser = true;
                    break;
                }
            }

            if (NativeMethods.OpenClipboard(Handle))
            {
                try
                {
                    s.HasHtmlFormat = NativeMethods.IsClipboardFormatAvailable(CF_HTML);
                    s.IsTextOnly = NativeMethods.IsClipboardFormatAvailable(NativeMethods.CF_UNICODETEXT)
                                   && !s.HasHtmlFormat;

                    if (NativeMethods.IsClipboardFormatAvailable(NativeMethods.CF_UNICODETEXT))
                    {
                        IntPtr hData = NativeMethods.GetClipboardData(NativeMethods.CF_UNICODETEXT);
                        if (hData != IntPtr.Zero)
                        {
                            string text = Marshal.PtrToStringUni(hData);
                            if (text != null)
                            {
                                s.ContentLength = text.Length;
                                s.ContentPreview = text.Length > Config.PreviewMaxChars
                                    ? text.Substring(0, Config.PreviewMaxChars) + "..."
                                    : text;
                            }
                        }
                    }
                }
                finally { NativeMethods.CloseClipboard(); }
            }

            CurrentState = s;

            if (s.IsBrowser)
            {
                Logger.Log($"CLIP: src={s.SourceProcess} pid={s.SourcePid} " +
                           $"html={s.HasHtmlFormat} textOnly={s.IsTextOnly} " +
                           $"len={s.ContentLength} seq={s.Sequence}");
            }
        }

        public void Cleanup()
        {
            NativeMethods.RemoveClipboardFormatListener(Handle);
            DestroyHandle();
        }
    }

    #endregion

    #region Execution Surface Detector

    static class ExecSurfaceDetector
    {
        public static bool Check(IntPtr hwnd, out string name)
        {
            name = "";
            uint pid;
            NativeMethods.GetWindowThreadProcessId(hwnd, out pid);

            string proc;
            try
            {
                using (var p = Process.GetProcessById((int)pid))
                    proc = p.ProcessName.ToLowerInvariant();
            }
            catch { return false; }

            foreach (var surface in Config.ExecSurfaces)
            {
                if (proc.Equals(surface, StringComparison.OrdinalIgnoreCase))
                {
                    name = proc;
                    return true;
                }
            }

            if (proc == "explorer")
            {
                var cls = new StringBuilder(256);
                NativeMethods.GetClassNameW(hwnd, cls, 256);
                if (cls.ToString() == "#32770")
                {
                    if (NativeMethods.FindWindowExW(hwnd, IntPtr.Zero, "ComboBox", null) != IntPtr.Zero)
                    {
                        name = "Run Dialog";
                        return true;
                    }
                }
            }

            return false;
        }
    }

    #endregion

    #region Keyboard Hook

    class KeyboardHook
    {
        private IntPtr _hookId = IntPtr.Zero;
        private readonly NativeMethods.LowLevelKeyboardProc _proc;
        private readonly ClipboardListener _clip;
        private volatile bool _busy = false;

        // When user clicks "Allow", we whitelist this sequence number.
        // Any Ctrl+V while the clipboard still has this sequence passes through.
        // Resets automatically when clipboard changes (new sequence from listener).
        private volatile uint _allowedSequence = 0;

        public KeyboardHook(ClipboardListener clip)
        {
            _clip = clip;
            _proc = Callback;
        }

        public bool Install()
        {
            using (var me = Process.GetCurrentProcess())
            using (var mod = me.MainModule)
            {
                _hookId = NativeMethods.SetWindowsHookEx(
                    NativeMethods.WH_KEYBOARD_LL, _proc,
                    NativeMethods.GetModuleHandle(mod.ModuleName), 0);
            }
            if (_hookId == IntPtr.Zero)
            {
                Logger.Log("ERROR: Hook install failed — need Administrator.");
                return false;
            }
            Logger.Log("Keyboard hook installed.");
            return true;
        }

        public void Uninstall()
        {
            if (_hookId != IntPtr.Zero)
            {
                NativeMethods.UnhookWindowsHookEx(_hookId);
                _hookId = IntPtr.Zero;
                Logger.Log("Keyboard hook removed.");
            }
        }

        private IntPtr Callback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)NativeMethods.WM_KEYDOWN && !_busy)
            {
                var ks = Marshal.PtrToStructure<NativeMethods.KBDLLHOOKSTRUCT>(lParam);

                bool ctrlV = ks.vkCode == NativeMethods.VK_V
                    && (NativeMethods.GetAsyncKeyState(NativeMethods.VK_CONTROL) & 0x8000) != 0
                    && (NativeMethods.GetAsyncKeyState(NativeMethods.VK_SHIFT) & 0x8000) == 0
                    && (NativeMethods.GetAsyncKeyState(NativeMethods.VK_MENU) & 0x8000) == 0;

                if (ctrlV)
                {
                    uint currentSeq = NativeMethods.GetClipboardSequenceNumber();
                    if (currentSeq == _allowedSequence)
                    {
                        Logger.Log($"PASS: seq={currentSeq} whitelisted by user.");
                        return NativeMethods.CallNextHookEx(_hookId, nCode, wParam, lParam);
                    }

                    IntPtr targetWindow = NativeMethods.GetForegroundWindow();
                    bool? isSuspicious = Evaluate();

                    if (isSuspicious.HasValue)
                    {
                        var state = _clip.CurrentState;
                        bool suspicious = isSuspicious.Value;
                        _busy = true;

                        ThreadPool.QueueUserWorkItem(_ =>
                        {
                            try { ShowDialog(state, suspicious, targetWindow); }
                            finally { _busy = false; }
                        });

                        return (IntPtr)1; // swallow
                    }
                }
            }
            return NativeMethods.CallNextHookEx(_hookId, nCode, wParam, lParam);
        }

        /// <summary>
        /// Returns null if no threat, true if suspicious (JS clipboard write),
        /// false if caution-only (strict mode, user-initiated copy).
        /// </summary>
        private bool? Evaluate()
        {
            var s = _clip.CurrentState;

            if (NativeMethods.GetClipboardSequenceNumber() != s.Sequence)
                return null;

            if (!s.IsBrowser)
                return null;

            string dest;
            if (!ExecSurfaceDetector.Check(NativeMethods.GetForegroundWindow(), out dest))
                return null;

            if (s.ContentLength < Config.MinContentLength)
                return null;

            Logger.Log($"GATES PASSED: src={s.SourceProcess} dst={dest} " +
                       $"len={s.ContentLength} html={s.HasHtmlFormat}");

            if (s.IsTextOnly && !s.HasHtmlFormat)
            {
                Logger.Log(">>> SUSPICIOUS: JS clipboard write — suspected ClickFix");
                return true;
            }
            else if (Config.StrictMode)
            {
                Logger.Log(">>> CAUTION (StrictMode): User copy from browser → exec surface");
                return false;
            }
            else
            {
                Logger.Log("User copy allowed (StrictMode off)");
                return null;
            }
        }

        private void ShowDialog(ClipboardState s, bool isSuspicious, IntPtr targetWindow)
        {
            string title, body;
            MessageBoxIcon icon;

            string preview =
                "────────────────────────────────\n" +
                s.ContentPreview + "\n" +
                "────────────────────────────────";

            string formatDesc = isSuspicious
                ? "Text only — no HTML Format (not from page content selection)"
                : "HTML Format present (user copied from browser)";

            string meta =
                $"Source:  {s.SourceProcess} (PID {s.SourcePid})\n" +
                $"Length:  {s.ContentLength} characters\n" +
                $"Format:  {formatDesc}";

            if (isSuspicious)
            {
                title = "ClipGuard — Suspicious Clipboard Paste";
                icon = MessageBoxIcon.Error;
                body =
                    "You are about to paste browser content into a command execution surface.\n\n" +
                    "This content was placed on the clipboard as plain text only (no HTML\n" +
                    "formatting). This happens when JavaScript writes to the clipboard — as in\n" +
                    "ClickFix attacks — but also when using copy buttons on sites like GitHub.\n\n" +
                    "If you did NOT just copy this yourself, BLOCK it immediately.\n\n" +
                    preview + "\n\n" + meta + "\n\n" +
                    "YES = Block the paste  (recommended)\n" +
                    "NO  = Allow the paste";
            }
            else
            {
                title = "ClipGuard — Paste Caution (Strict Mode)";
                icon = MessageBoxIcon.Warning;
                body =
                    "You are pasting browser content into a command execution surface.\n\n" +
                    "You copied this from a webpage — verify it's safe before running.\n\n" +
                    preview + "\n\n" + meta + "\n\n" +
                    "YES = Block the paste\n" +
                    "NO  = Allow the paste";
            }

            var result = MessageBox.Show(body, title,
                MessageBoxButtons.YesNo, icon,
                MessageBoxDefaultButton.Button1,
                MessageBoxOptions.DefaultDesktopOnly);

            if (result == DialogResult.No)
            {
                Logger.Log($"User ALLOWED paste. Whitelisting seq={s.Sequence}");
                _allowedSequence = s.Sequence;
                ForceForeground(targetWindow);
                Thread.Sleep(500);
                ReplayCtrlV();
            }
            else
            {
                Logger.Log("User BLOCKED paste.");
            }
        }

        private void ForceForeground(IntPtr targetWindow)
        {
            try
            {
                uint targetThreadId = NativeMethods.GetWindowThreadProcessId(targetWindow, out uint _);
                uint ourThread = NativeMethods.GetCurrentThreadId();

                NativeMethods.AttachThreadInput(ourThread, targetThreadId, true);
                NativeMethods.SetForegroundWindow(targetWindow);
                NativeMethods.AttachThreadInput(ourThread, targetThreadId, false);

                Logger.Log($"Focus restored to HWND {targetWindow}");
            }
            catch (Exception ex)
            {
                Logger.Log($"ForceForeground failed: {ex.Message}");
                NativeMethods.SetForegroundWindow(targetWindow);
            }
        }

        private void ReplayCtrlV()
        {
            var inp = new NativeMethods.INPUT[4];

            inp[0].type = NativeMethods.INPUT_KEYBOARD;
            inp[0].u.ki.wVk = (ushort)NativeMethods.VK_CONTROL;

            inp[1].type = NativeMethods.INPUT_KEYBOARD;
            inp[1].u.ki.wVk = (ushort)NativeMethods.VK_V;

            inp[2].type = NativeMethods.INPUT_KEYBOARD;
            inp[2].u.ki.wVk = (ushort)NativeMethods.VK_V;
            inp[2].u.ki.dwFlags = NativeMethods.KEYEVENTF_KEYUP;

            inp[3].type = NativeMethods.INPUT_KEYBOARD;
            inp[3].u.ki.wVk = (ushort)NativeMethods.VK_CONTROL;
            inp[3].u.ki.dwFlags = NativeMethods.KEYEVENTF_KEYUP;

            NativeMethods.SendInput(4, inp, Marshal.SizeOf<NativeMethods.INPUT>());
            Logger.Log("Ctrl+V replayed.");
        }
    }

    #endregion

    #region Tray Application

    class ClipGuardApp : ApplicationContext
    {
        private NotifyIcon _tray;
        private ClipboardListener _clip;
        private KeyboardHook _hook;
        private ToolStripMenuItem _strictItem;

        public ClipGuardApp()
        {
            _clip = new ClipboardListener();
            _hook = new KeyboardHook(_clip);

            if (!_hook.Install())
            {
                MessageBox.Show(
                    "Failed to install keyboard hook.\nPlease run as Administrator.",
                    "ClipGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            _tray = new NotifyIcon
            {
                Icon = MakeIcon(),
                Text = "ClipGuard — Active",
                Visible = true,
                ContextMenuStrip = MakeMenu()
            };

            _tray.ShowBalloonTip(2000, "ClipGuard",
                "Monitoring for ClickFix attacks.", ToolTipIcon.Info);

            Logger.Log("ClipGuard ready.");
        }

        private ContextMenuStrip MakeMenu()
        {
            var m = new ContextMenuStrip();
            m.Items.Add(new ToolStripMenuItem("ClipGuard") { Enabled = false });
            m.Items.Add(new ToolStripSeparator());

            m.Items.Add("Status", null, (sender, args) =>
            {
                var s = _clip.CurrentState;
                MessageBox.Show(
                    "ClipGuard is running.\n\n" +
                    $"Strict Mode: {Config.StrictMode}\n" +
                    $"Last clipboard source: {s.SourceProcess}\n" +
                    $"Browser: {s.IsBrowser}\n" +
                    $"HTML Format: {s.HasHtmlFormat}\n" +
                    $"Text Only: {s.IsTextOnly}\n" +
                    $"Length: {s.ContentLength}\n" +
                    $"Seq: {s.Sequence}\n\n" +
                    $"Log: {Logger.LogFilePath}",
                    "ClipGuard Status", MessageBoxButtons.OK, MessageBoxIcon.Information);
            });

            m.Items.Add("Open Log", null, (sender, args) =>
            {
                try { Process.Start("notepad.exe", Logger.LogFilePath); } catch { }
            });

            _strictItem = new ToolStripMenuItem("Strict Mode")
            {
                CheckOnClick = true,
                Checked = Config.StrictMode,
                ToolTipText = "ON = also warn on user Ctrl+C from browser → exec surface"
            };
            _strictItem.CheckedChanged += (sender, args) =>
            {
                Config.StrictMode = _strictItem.Checked;
                Logger.Log($"StrictMode toggled: {Config.StrictMode}");
            };
            m.Items.Add(_strictItem);

            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("Exit", null, (sender, args) => Shutdown());
            return m;
        }

        private void Shutdown()
        {
            Logger.Log("ClipGuard stopped.");
            _hook.Uninstall();
            _clip.Cleanup();
            _tray.Visible = false;
            _tray.Dispose();
            WinApp.Exit();
        }

        private Icon MakeIcon()
        {
            var bmp = new Bitmap(16, 16);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                g.FillPolygon(Brushes.ForestGreen, new[] {
                    new Point(8, 1),  new Point(14, 3), new Point(14, 9),
                    new Point(8, 15), new Point(2, 9),  new Point(2, 3)
                });
                using (var pen = new Pen(Color.White, 2))
                {
                    g.DrawLine(pen, 5, 8, 7, 11);
                    g.DrawLine(pen, 7, 11, 11, 5);
                }
            }
            return Icon.FromHandle(bmp.GetHicon());
        }
    }

    #endregion

    #region Entry Point

    static class Program
    {
        [STAThread]
        static void Main()
        {
            bool created;
            using (var mtx = new Mutex(true, "ClipGuard_SingleInstance", out created))
            {
                if (!created)
                {
                    MessageBox.Show("ClipGuard is already running.",
                        "ClipGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                Logger.Log( "ClipGuard starting");
                WinApp.EnableVisualStyles();
                WinApp.SetCompatibleTextRenderingDefault(false);
                WinApp.Run(new ClipGuardApp());
            }
        }
    }

    #endregion
}
