using AdvancedDataGridView;
using PcapNet;
using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace SelfishNetv3
{
#pragma warning disable  // Falta el comentario XML para el tipo o miembro visible públicamente
    public delegate void delegateOnNewPC(PC pc);

    public delegate void DelUpdateName(PC pc, string str);
    public partial class ArpForm : Form
    {

        public int timerStatCount;
        public Driver driver;
        public PcList pcs;
        public CArp cArp;
        public CAdapter cAdapter;
        public byte[] routerIP;
        public object[] resolvState;
        public NetworkInterface nicNet;
        public static ArpForm instance;
        private Panel advancedNetworkPanel;
        private ComboBox comboAdvancedAdapters;
        private TextBox textCustomSubnets;
        private TextBox textDiagnostics;
        private CheckBox checkGuestDiscovery;
        private CheckBox checkForceSubnetScan;
        private Button buttonApplyAdapter;
        private Button buttonRefreshInterfaces;
        private Button buttonForceScan;
        private Button buttonDiagnostics;
        private ToolStripButton toolStripButtonAdvanced;
        private NetworkDiscoveryEngine discoveryEngine;
        private List<NetworkAdapterInfo> advancedAdapters;
        private Thread discoveryThread;
        private bool discoveryRunning;
        private int discoveryGeneration;
        public ArpForm()
        {
            InitializeComponent();
            ArpForm.instance = this;
            this.timerStatCount = 0;
            this.driver = new Driver();
            this.discoveryEngine = new NetworkDiscoveryEngine();
            this.advancedAdapters = new List<NetworkAdapterInfo>();
            InitializeAdvancedNetworkControls();
        }
        public void licenseAccepted()
        {
            if (!this.driver.create())
            {
                int num = (int)MessageBox.Show("problem installing the drivers, do you have administrator privileges?");
                if (this == null)
                    return;
                this.Dispose();
            }
            else
            {
                CAdapter cadapter = new CAdapter();
                this.cAdapter = cadapter;
                if (!minimized) cadapter.Show((IWin32Window)this);
            }
        }

        private void InitializeAdvancedNetworkControls()
        {
            toolStripButtonAdvanced = new ToolStripButton("Advanced");
            toolStripButtonAdvanced.CheckOnClick = true;
            toolStripButtonAdvanced.DisplayStyle = ToolStripItemDisplayStyle.Text;
            toolStripButtonAdvanced.Click += new EventHandler(ToolStripButtonAdvanced_Click);
            toolStrip1.Items.Add(toolStripButtonAdvanced);

            advancedNetworkPanel = new Panel();
            advancedNetworkPanel.Visible = false;
            advancedNetworkPanel.BorderStyle = BorderStyle.FixedSingle;
            advancedNetworkPanel.BackColor = System.Drawing.SystemColors.Control;
            advancedNetworkPanel.Height = 190;
            advancedNetworkPanel.Left = 0;
            advancedNetworkPanel.Top = toolStrip1.Bottom;
            advancedNetworkPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            advancedNetworkPanel.Width = this.ClientSize.Width;

            Label labelAdapter = new Label();
            labelAdapter.Text = "Adapter";
            labelAdapter.Left = 8;
            labelAdapter.Top = 12;
            labelAdapter.Width = 56;
            advancedNetworkPanel.Controls.Add(labelAdapter);

            comboAdvancedAdapters = new ComboBox();
            comboAdvancedAdapters.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAdvancedAdapters.Left = 70;
            comboAdvancedAdapters.Top = 8;
            comboAdvancedAdapters.Width = 430;
            advancedNetworkPanel.Controls.Add(comboAdvancedAdapters);

            buttonApplyAdapter = new Button();
            buttonApplyAdapter.Text = "Apply";
            buttonApplyAdapter.Left = 510;
            buttonApplyAdapter.Top = 6;
            buttonApplyAdapter.Width = 70;
            buttonApplyAdapter.Click += new EventHandler(ButtonApplyAdapter_Click);
            advancedNetworkPanel.Controls.Add(buttonApplyAdapter);

            buttonRefreshInterfaces = new Button();
            buttonRefreshInterfaces.Text = "Refresh";
            buttonRefreshInterfaces.Left = 586;
            buttonRefreshInterfaces.Top = 6;
            buttonRefreshInterfaces.Width = 80;
            buttonRefreshInterfaces.Click += new EventHandler(ButtonRefreshInterfaces_Click);
            advancedNetworkPanel.Controls.Add(buttonRefreshInterfaces);

            checkGuestDiscovery = new CheckBox();
            checkGuestDiscovery.Text = "Guest discovery";
            checkGuestDiscovery.Left = 680;
            checkGuestDiscovery.Top = 10;
            checkGuestDiscovery.Width = 130;
            checkGuestDiscovery.Checked = true;
            advancedNetworkPanel.Controls.Add(checkGuestDiscovery);

            checkForceSubnetScan = new CheckBox();
            checkForceSubnetScan.Text = "Force scan";
            checkForceSubnetScan.Left = 820;
            checkForceSubnetScan.Top = 10;
            checkForceSubnetScan.Width = 100;
            advancedNetworkPanel.Controls.Add(checkForceSubnetScan);

            Label labelCustom = new Label();
            labelCustom.Text = "Custom CIDR/range";
            labelCustom.Left = 8;
            labelCustom.Top = 45;
            labelCustom.Width = 120;
            advancedNetworkPanel.Controls.Add(labelCustom);

            textCustomSubnets = new TextBox();
            textCustomSubnets.Left = 132;
            textCustomSubnets.Top = 42;
            textCustomSubnets.Width = 368;
            advancedNetworkPanel.Controls.Add(textCustomSubnets);

            buttonForceScan = new Button();
            buttonForceScan.Text = "Scan";
            buttonForceScan.Left = 510;
            buttonForceScan.Top = 40;
            buttonForceScan.Width = 70;
            buttonForceScan.Click += new EventHandler(ButtonForceScan_Click);
            advancedNetworkPanel.Controls.Add(buttonForceScan);

            buttonDiagnostics = new Button();
            buttonDiagnostics.Text = "Diagnostics";
            buttonDiagnostics.Left = 586;
            buttonDiagnostics.Top = 40;
            buttonDiagnostics.Width = 100;
            buttonDiagnostics.Click += new EventHandler(ButtonDiagnostics_Click);
            advancedNetworkPanel.Controls.Add(buttonDiagnostics);

            textDiagnostics = new TextBox();
            textDiagnostics.Left = 8;
            textDiagnostics.Top = 76;
            textDiagnostics.Width = advancedNetworkPanel.Width - 16;
            textDiagnostics.Height = 106;
            textDiagnostics.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textDiagnostics.Multiline = true;
            textDiagnostics.ReadOnly = true;
            textDiagnostics.ScrollBars = ScrollBars.Vertical;
            advancedNetworkPanel.Controls.Add(textDiagnostics);

            this.Controls.Add(advancedNetworkPanel);
            advancedNetworkPanel.BringToFront();
            toolStrip1.BringToFront();
            RefreshAdvancedAdapters();
            AdjustAdvancedNetworkLayout();
        }

        private void ToolStripButtonAdvanced_Click(object sender, EventArgs e)
        {
            advancedNetworkPanel.Visible = toolStripButtonAdvanced.Checked;
            if (advancedNetworkPanel.Visible)
            {
                RefreshAdvancedAdapters();
            }
            AdjustAdvancedNetworkLayout();
        }

        private void AdjustAdvancedNetworkLayout()
        {
            if (advancedNetworkPanel == null)
            {
                return;
            }

            advancedNetworkPanel.Top = toolStrip1.Bottom;
            advancedNetworkPanel.Width = this.ClientSize.Width;
            textDiagnostics.Width = advancedNetworkPanel.Width - 16;
            int top = advancedNetworkPanel.Visible ? advancedNetworkPanel.Bottom + 5 : 60;
            treeGridView1.Top = top;
            treeGridView1.Height = this.ClientSize.Height - top;
        }

        private void RefreshAdvancedAdapters()
        {
            if (comboAdvancedAdapters == null)
            {
                return;
            }

            List<string> diagnostics = new List<string>();
            advancedAdapters = NetworkDiscoveryEngine.GetAdapters(diagnostics);
            comboAdvancedAdapters.Items.Clear();
            int selectedIndex = -1;
            for (int i = 0; i < advancedAdapters.Count; i++)
            {
                NetworkAdapterInfo adapter = advancedAdapters[i];
                comboAdvancedAdapters.Items.Add(adapter.DisplayName);
                if (nicNet != null && adapter.Interface.Id == nicNet.Id)
                {
                    selectedIndex = i;
                }
            }

            if (comboAdvancedAdapters.Items.Count > 0)
            {
                comboAdvancedAdapters.SelectedIndex = selectedIndex >= 0 ? selectedIndex : 0;
            }
        }

        private void ButtonRefreshInterfaces_Click(object sender, EventArgs e)
        {
            RefreshAdvancedAdapters();
            ShowDiagnosticsOnly();
        }

        private void ButtonApplyAdapter_Click(object sender, EventArgs e)
        {
            if (comboAdvancedAdapters.SelectedIndex < 0 || comboAdvancedAdapters.SelectedIndex >= advancedAdapters.Count)
            {
                return;
            }

            if (!advancedAdapters[comboAdvancedAdapters.SelectedIndex].HasIPv4 || !advancedAdapters[comboAdvancedAdapters.SelectedIndex].IsUp)
            {
                MessageBox.Show("Select an active adapter with an IPv4 address.");
                return;
            }

            NicIsSelected(advancedAdapters[comboAdvancedAdapters.SelectedIndex].Interface);
        }

        private void ButtonForceScan_Click(object sender, EventArgs e)
        {
            RunEnhancedDiscovery(true);
        }

        private void ButtonDiagnostics_Click(object sender, EventArgs e)
        {
            ShowDiagnosticsOnly();
        }

        private void ShowDiagnosticsOnly()
        {
            List<string> diagnostics = new List<string>();
            NetworkDiscoveryEngine.GetAdapters(diagnostics);
            textDiagnostics.Text = string.Join(Environment.NewLine, diagnostics.ToArray());
        }

        private void RunEnhancedDiscovery(bool forceScan)
        {
            if (discoveryRunning || pcs == null)
            {
                return;
            }

            discoveryRunning = true;
            buttonForceScan.Enabled = false;
            if (textDiagnostics != null)
            {
                textDiagnostics.Text = "Discovery running...";
            }

            NetworkDiscoveryOptions options = new NetworkDiscoveryOptions();
            options.SelectedInterface = nicNet;
            options.SelectedInterfaceHasGateway = cArp != null && cArp.HasRouter;
            options.GuestDetectionMode = checkGuestDiscovery == null || checkGuestDiscovery.Checked;
            options.ForceLargeScans = forceScan || (checkForceSubnetScan != null && checkForceSubnetScan.Checked);
            options.CustomSubnets = textCustomSubnets == null ? string.Empty : textCustomSubnets.Text;
            if (options.ForceLargeScans)
            {
                options.MaxHostsPerSubnet = 4096;
            }
            int runGeneration = discoveryGeneration;

            discoveryThread = new Thread(delegate()
            {
                NetworkDiscoveryResult result = null;
                try
                {
                    result = discoveryEngine.Scan(options);
                    if (!IsDisposed && IsHandleCreated)
                    {
                        BeginInvoke((MethodInvoker)delegate()
                        {
                            if (runGeneration != discoveryGeneration)
                            {
                                discoveryRunning = false;
                                buttonForceScan.Enabled = true;
                                return;
                            }
                            MergeDiscoveryResult(result);
                            discoveryRunning = false;
                            buttonForceScan.Enabled = true;
                            if (textDiagnostics != null)
                            {
                                textDiagnostics.Text = string.Join(Environment.NewLine, result.Diagnostics.ToArray());
                            }
                        });
                    }
                    else
                    {
                        discoveryRunning = false;
                    }
                }
                catch
                {
                    discoveryRunning = false;
                    try
                    {
                        if (!IsDisposed && IsHandleCreated)
                        {
                            BeginInvoke((MethodInvoker)delegate()
                            {
                                buttonForceScan.Enabled = true;
                                if (textDiagnostics != null)
                                {
                                    textDiagnostics.Text = "Discovery failed. See permissions, adapter, or Npcap/WinPcap status.";
                                }
                            });
                        }
                    }
                    catch
                    {
                    }
                }
            });
            discoveryThread.IsBackground = true;
            discoveryThread.Start();
        }

        private void MergeDiscoveryResult(NetworkDiscoveryResult result)
        {
            if (result == null || pcs == null)
            {
                return;
            }

            foreach (DiscoveredDevice device in result.Devices)
            {
                if (cArp != null && cArp.localIP != null && tools.areValuesEqual(device.IP.GetAddressBytes(), cArp.localIP))
                {
                    continue;
                }

                PC pc = new PC();
                pc.ip = device.IP;
                pc.mac = NetworkDiscoveryEngine.HasUsableMac(device.Mac) ? device.Mac : PhysicalAddress.None;
                pc.capDown = 0;
                pc.capUp = 0;
                pc.isLocalPc = false;
                pc.name = string.Empty;
                pc.nbPacketReceivedSinceLastReset = 0;
                pc.nbPacketSentSinceLastReset = 0;
                pc.redirect = device.CanRedirect;
                pc.canRedirect = device.CanRedirect;
                pc.discoverySource = device.Source;
                pc.timeSinceLastRarp = DateTime.Now;
                pc.totalPacketReceived = 0;
                pc.totalPacketSent = 0;
                pc.isGateway = cArp != null && cArp.routerIP != null && tools.areValuesEqual(device.IP.GetAddressBytes(), cArp.routerIP);
                pcs.addPcToList(pc);
            }
        }

        bool first_start;
        bool minimized;

        public void NicIsSelected(NetworkInterface nic)
        {
            StopCurrentNetworkSession();
            ResetDeviceTree();
            this.pcs = new PcList();
            this.pcs.SetCallBackOnNewPC(new delegateOnNewPC(this.callbackOnNewPC));
            this.pcs.SetCallBackOnPCRemove(new delegateOnNewPC(this.callbackOnPCRemove));
            this.nicNet = nic;
            CArp carp = new CArp(nic, this.pcs);
            this.cArp = carp;
            if (this.cArp.localIP == null || this.cArp.localMAC == null)
            {
                MessageBox.Show("The selected adapter does not have an IPv4 address.");
                return;
            }
            carp.startArpListener();
            if (this.cArp.HasRouter)
            {
                this.cArp.findMacRouter();
            }
            else
            {
                this.treeGridView1.Nodes[0].Cells[0].Value = (object)"No IPv4 gateway";
                this.treeGridView1.Nodes[0].Cells[1].Value = (object)string.Empty;
                this.treeGridView1.Nodes[0].Cells[2].Value = (object)string.Empty;
            }
            PC pc = new PC();
            pc.ip = new IPAddress(this.cArp.localIP);
            pc.mac = new PhysicalAddress(this.cArp.localMAC);
            pc.capDown = 0;
            pc.capUp = 0;
            pc.isLocalPc = true;
            pc.name = string.Empty;
            pc.nbPacketReceivedSinceLastReset = 0;
            pc.nbPacketSentSinceLastReset = 0;
            pc.redirect = false;
            pc.canRedirect = false;
            pc.discoverySource = "selected interface";
            DateTime now = DateTime.Now;
            pc.timeSinceLastRarp = (ValueType)now;
            pc.totalPacketReceived = 0;
            pc.totalPacketSent = 0;
            pc.isGateway = false;
            this.pcs.addPcToList(pc);
            this.timer2.Interval = 5000;
            this.timer2.Start();
            this.treeGridView1.Nodes[0].Expand();
            RefreshAdvancedAdapters();
            RunEnhancedDiscovery(false);
        }

        private void StopCurrentNetworkSession()
        {
            timer1.Stop();
            timer2.Stop();
            timerSpoof.Stop();
            timerDiscovery.Stop();
            discoveryGeneration++;
            discoveryRunning = false;
            toolStripButton2.Checked = false;
            toolStripButton2.Enabled = true;
            if (cArp != null)
            {
                cArp.Dispose();
                cArp = null;
            }
        }

        private void ResetDeviceTree()
        {
            if (treeGridView1.Nodes.Count == 0)
            {
                treeGridView1.Nodes.Add(new AdvancedDataGridView.TreeGridNode());
            }

            while (treeGridView1.Nodes[0].Nodes.Count > 0)
            {
                treeGridView1.Nodes[0].Nodes.RemoveAt(0);
            }

            for (int i = 0; i < treeGridView1.Nodes[0].Cells.Count; i++)
            {
                treeGridView1.Nodes[0].Cells[i].Value = null;
                treeGridView1.Nodes[0].Cells[i].ReadOnly = true;
            }
            treeGridView1.Nodes[0].ImageIndex = 0;
        }

        [Obsolete]
        private void callbackOnNewPC(PC pc)
        {
            object[] objArray = new object[1] { (object)pc };
            ArpForm arpForm = this;
            arpForm.Invoke((Delegate)new delegateOnNewPC(arpForm.AddPc), objArray);
            Dns.BeginResolve(pc.ip.ToString(), new AsyncCallback(this.EndResolvCallBack), pc);
        }

        [Obsolete]
        private void EndResolvCallBack(IAsyncResult re)
        {
            string str = (string)null;
            PC asyncState = (PC)re.AsyncState;
            try
            {
                str = Dns.EndResolve(re).HostName;
                if (str == (string)null)
                    str = "noname";
                object[] objArray = new object[2];
                this.resolvState = objArray;
                objArray[0] = (object)asyncState;
                this.resolvState[1] = (object)str;
                this.Invoke((Delegate)new DelUpdateName(this.updateTreeViewNameCallBack), this.resolvState);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }

        private void updateTreeViewNameCallBack(PC pc, string str)
        {
            if (pc.isGateway)
            {
                this.treeGridView1.Nodes[0].Cells[0].Value = (object)str;
                this.treeGridView1.Nodes[0].ImageIndex = 1;
            }
            else
            {
                int index = 1;
                if (1 >= this.treeGridView1.Nodes[0].Nodes.Count)
                    return;
                while (this.treeGridView1.Nodes[0].Nodes[index].Cells[1].Value.ToString().CompareTo(pc.ip.ToString()) != 0)
                {
                    ++index;
                    if (index >= this.treeGridView1.Nodes[0].Nodes.Count)
                        return;
                }
                this.treeGridView1.Nodes[0].Nodes[index].Cells[0].Value = (object)str;
            }
        }

        private void callbackOnPCRemove(PC pc)
        {
            int index = 1;
            if (1 >= this.treeGridView1.Nodes[0].Nodes.Count)
                return;
            while (this.treeGridView1.Nodes[0].Nodes[index].Cells[1].Value.ToString().CompareTo(pc.ip.ToString()) != 0)
            {
                ++index;
                if (index >= this.treeGridView1.Nodes[0].Nodes.Count)
                    return;
            }
            this.treeGridView1.Nodes[0].Nodes.RemoveAt(index);
        }

        private void AddPc(PC pc)
        {
            string macText = NetworkDiscoveryEngine.HasUsableMac(pc.mac) ? pc.mac.ToString() : "N/A";
            if (pc.isGateway)
            {
                this.treeGridView1.Nodes[0].Cells[1].Value = (object)pc.ip.ToString();
                this.treeGridView1.Nodes[0].Cells[2].Value = (object)macText;
                this.treeGridView1.Nodes[0].Cells[5].ReadOnly = true;
                this.treeGridView1.Nodes[0].Cells[6].ReadOnly = true;
                this.treeGridView1.Nodes[0].Cells[7].ReadOnly = true;
                this.treeGridView1.Nodes[0].Cells[8].ReadOnly = true;
                this.treeGridView1.Nodes[0].Cells[5].Value = (object)0;
                this.treeGridView1.Nodes[0].Cells[6].Value = (object)0;
                this.treeGridView1.Nodes[0].Cells[7].ReadOnly = true;
                this.treeGridView1.Nodes[0].Cells[8].ReadOnly = true;
            }
            else if (pc.isLocalPc)
            {
                TreeGridNode treeGridNode = this.treeGridView1.Nodes[0].Nodes.Add((object)"Your PC", (object)pc.ip, (object)macText);
                treeGridNode.ImageIndex = 0;
                treeGridNode.Cells[5].Value = (object)0;
                treeGridNode.Cells[6].Value = (object)0;
                treeGridNode.Cells[5].ReadOnly = true;
                treeGridNode.Cells[6].ReadOnly = true;
                treeGridNode.Cells[7].Value = (object)false;
                treeGridNode.Cells[8].Value = (object)false;
                treeGridNode.Cells[7].ReadOnly = true;
                treeGridNode.Cells[8].ReadOnly = true;
            }
            else
            {
                TreeGridNode treeGridNode = this.treeGridView1.Nodes[0].Nodes.Add((object)string.Empty, (object)pc.ip, (object)macText, (object)string.Empty, (object)string.Empty, (object)0, (object)0, (object)false, (object)pc.canRedirect);
                treeGridNode.ImageIndex = 0;
                treeGridNode.Cells[5].ReadOnly = !pc.canRedirect;
                treeGridNode.Cells[6].ReadOnly = !pc.canRedirect;
                treeGridNode.Cells[7].ReadOnly = !pc.canRedirect;
                treeGridNode.Cells[8].ReadOnly = !pc.canRedirect;
            }
        }
        private void ToolStripButton1_Click(object sender, EventArgs e)
        {
            if (this.cArp != null)
            {
                this.cArp.startArpDiscovery();
            }
            RunEnhancedDiscovery(false);
        }

        private void ToolStripButton2_Click(object sender, EventArgs e)
        {
            if (this.toolStripButton2.Checked || this.cArp == null)
                return;
            if (this.cArp.startRedirector() != 0)
                return;
            this.toolStripButton2.Checked = true;
            this.timer1.Interval = 1000;
            this.timer1.Start();
            this.timerSpoof.Start();
            this.timerSpoof.Interval = 2000;
            this.toolStripButton2.Checked = true;
            this.toolStripButton2.Enabled = false;
            this.timerDiscovery.Start();
        }

        private void ToolStripButton3_Click(object sender, EventArgs e)
        {
            if (!this.toolStripButton2.Checked || this.cArp == null)
                return;
            this.cArp.stopRedirector();
            this.cArp.completeUnspoof();
            this.timer1.Stop();
            this.timerSpoof.Stop();
            int index = 0;
            if (0 < this.treeGridView1.Nodes[0].Nodes.Count)
            {
                do
                {
                    this.treeGridView1.Nodes[0].Nodes[index].Cells[3].Value = (object)string.Empty;
                    this.treeGridView1.Nodes[0].Nodes[index].Cells[4].Value = (object)string.Empty;
                    ++index;
                }
                while (index < this.treeGridView1.Nodes[0].Nodes.Count);
            }
            this.toolStripButton2.Checked = false;
            this.toolStripButton2.Enabled = true;
            this.timerDiscovery.Stop();
        }

        private void ToolStripButton4_Click(object sender, EventArgs e)
        {
            if (System.IO.File.Exists("hlpindex.html"))
            {
                Process.Start("hlpindex.html");
            }
            else
            {
                int num = (int)MessageBox.Show("help file is missing !");
            }
        }

        private void TreeGridView1_CurrentCellDirtyStateChanged(object sender, EventArgs e)
        {
            if (this.treeGridView1.CurrentCell.ColumnIndex < 7 && (this.treeGridView1.CurrentCell.ColumnIndex < 8 || !this.treeGridView1.IsCurrentCellDirty))
                return;
            this.treeGridView1.CommitEdit(DataGridViewDataErrorContexts.Commit);
        }

        private void TreeGridView1_CellValueChanged(object sender, DataGridViewCellEventArgs e)
        {
            try
            {
                if (e.ColumnIndex == 5 && e.RowIndex >= 2)
                {
                    IPAddress ipAddress = tools.getIpAddress(this.treeGridView1.Rows[e.RowIndex].Cells[1].Value.ToString());
                    if (this.treeGridView1.Rows[e.RowIndex].Cells[0].Value.ToString().CompareTo(string.Empty) != 0)
                    {
                        PC pcFromIp = this.pcs.getPCFromIP(ipAddress.GetAddressBytes());
                        if (pcFromIp != null)
                        {
                            Monitor.Enter((object)pcFromIp);
                            pcFromIp.capDown = Convert.ToInt32(this.treeGridView1.Rows[e.RowIndex].Cells[5].Value) * 1024;
                            Monitor.Exit((object)pcFromIp);
                        }
                    }
                }
                if (e.ColumnIndex == 6 && e.RowIndex >= 2)
                {
                    IPAddress ipAddress = tools.getIpAddress(this.treeGridView1.Rows[e.RowIndex].Cells[1].Value.ToString());
                    if (this.treeGridView1.Rows[e.RowIndex].Cells[0].Value.ToString().CompareTo(string.Empty) != 0)
                    {
                        PC pcFromIp = this.pcs.getPCFromIP(ipAddress.GetAddressBytes());
                        if (pcFromIp != null)
                        {
                            Monitor.Enter((object)pcFromIp);
                            pcFromIp.capUp = Convert.ToInt32(this.treeGridView1.Rows[e.RowIndex].Cells[6].Value) * 1024;
                            Monitor.Exit((object)pcFromIp);
                        }
                    }
                }
                if (e.ColumnIndex == 7 && e.RowIndex >= 2)
                {
                    IPAddress ipAddress = tools.getIpAddress(this.treeGridView1.Rows[e.RowIndex].Cells[1].Value.ToString());
                    if (this.treeGridView1.Rows[e.RowIndex].Cells[0].Value.ToString().CompareTo(string.Empty) != 0)
                    {
                        PC pcFromIp = this.pcs.getPCFromIP(ipAddress.GetAddressBytes());
                        if (pcFromIp != null)
                        {
                            Monitor.Enter((object)pcFromIp);
                            int num = !pcFromIp.redirect ? 1 : 0;
                            pcFromIp.redirect = num != 0;
                            Monitor.Exit((object)pcFromIp);
                        }
                    }
                }
                if (e.ColumnIndex != 8 || e.RowIndex < 2 || this.treeGridView1.Rows[e.RowIndex].Cells[0].Value.ToString().CompareTo(string.Empty) == 0)
                    return;
                IPAddress ipAddress1 = tools.getIpAddress(this.treeGridView1.Rows[e.RowIndex].Cells[1].Value.ToString());
                if (this.treeGridView1.Rows[e.RowIndex].Cells[8].Value.ToString().CompareTo("False") != 0)
                    return;
                if (this.cArp == null || !this.cArp.HasRouter)
                    return;
                for (int index = 0; index < 35; ++index)
                    this.cArp.UnSpoof(ipAddress1, new IPAddress(this.cArp.routerIP));

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private unsafe void ArpForm_Load(object sender, EventArgs e)
        {

            if (args.Length > 1)
            {
                if (args[1] == "minimize")
                {
                    first_start = true;
                    minimized = true;
                }
            }


            this.Text = "SelfishNet v" + Application.ProductVersion.ToString();
            //this.Icon = SelfishNetv3.Properties.Resources.nov0caina_icon;
            //SelfishNetTrayIcon.Icon = SelfishNetv3.Properties.Resources.nov0caina_icon.ico;
            if ((IntPtr)this.driver.openDeviceDriver((sbyte*)(void*)Marshal.StringToHGlobalAnsi("npf")) == IntPtr.Zero)
            {
                if (System.IO.File.Exists("license.txt"))
                {
                    CWizard cwizard = new CWizard();
                    cwizard.Show((IWin32Window)this);
                    Decoder decoder = Encoding.UTF7.GetDecoder();
                    FileStream fileStream = System.IO.File.OpenRead("license.txt");
                    byte[] numArray = new byte[(int)fileStream.Length];
                    fileStream.Read(numArray, 0, (int)fileStream.Length);
                    char[] chars = new char[decoder.GetCharCount(numArray, 0, numArray.Length)];
                    decoder.GetChars(numArray, 0, numArray.Length, chars, 0);
                    cwizard.richTextBox1.Text = new string(chars);
                    fileStream.Close();
                }
                else
                    this.licenseAccepted();
            }
            else
            {
                int num = (int)MessageBox.Show("Driver WinPcap already installed");
            }
        }

        private void Timer1_Tick(object sender, EventArgs e)
        {
            ++this.timerStatCount;
            for (int index = 0; index < this.treeGridView1.Nodes[0].Nodes.Count; ++index)
            {
                try
                {
                    PC pcFromIp = this.pcs.getPCFromIP(tools.getIpAddress(this.treeGridView1.Nodes[0].Nodes[index].Cells[1].Value.ToString()).GetAddressBytes());
                    string str1 = ((float)pcFromIp.nbPacketReceivedSinceLastReset * 0.0009765625f / (float)(this.timer1.Interval / 1000) / (float)this.timerStatCount).ToString();
                    string str2 = ((float)pcFromIp.nbPacketSentSinceLastReset * 0.0009765625f / (float)(this.timer1.Interval / 1000) / (float)this.timerStatCount).ToString();
                    if (str1.Length - str1.IndexOf(".") > 1)
                    {
                        int num = -2 - str1.IndexOf(".");
                        string str3 = str1;
                        str1 = str3.Remove(str3.IndexOf(".") + 1, str1.Length + num);
                    }
                    if (str2.Length - str2.IndexOf(".") > 1)
                    {
                        int num = -2 - str2.IndexOf(".");
                        string str3 = str2;
                        str2 = str3.Remove(str3.IndexOf(".") + 1, str2.Length + num);
                    }
                    this.treeGridView1.Nodes[0].Nodes[index].Cells[3].Value = (object)str1;
                    this.treeGridView1.Nodes[0].Nodes[index].Cells[4].Value = (object)str2;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            this.pcs.ResetAllPacketsCount();
            this.timerStatCount = 0;
        }

        private void Timer2_Tick(object sender, EventArgs e)
        {
            if (this.cArp == null)
                return;
            int index1 = 0;
            if (0 < this.treeGridView1.Nodes[0].Nodes.Count)
            {
                do
                {
                    PC pcFromIp = this.pcs.getPCFromIP(tools.getIpAddress(this.treeGridView1.Nodes[0].Nodes[index1].Cells[1].Value.ToString()).GetAddressBytes());
                    if (pcFromIp != null && !pcFromIp.isGateway && !pcFromIp.isLocalPc && DateTime.Now.Ticks - ((DateTime)pcFromIp.timeSinceLastRarp).Ticks > 3500000000L)
                    {
                        this.pcs.removePcFromList(pcFromIp);
                        index1 = 0;
                    }
                    ++index1;
                }
                while (index1 < this.treeGridView1.Nodes[0].Nodes.Count);
            }
            int index2 = 0;
            if (0 >= this.treeGridView1.Nodes[0].Nodes.Count)
                return;
            do
            {
                PC pcFromIp = this.pcs.getPCFromIP(tools.getIpAddress(this.treeGridView1.Nodes[0].Nodes[index2].Cells[1].Value.ToString()).GetAddressBytes());
                if (pcFromIp != null && DateTime.Now.Ticks - ((DateTime)pcFromIp.timeSinceLastRarp).Ticks > 200000000L)
                    this.cArp.findMac(pcFromIp.ip.ToString());
                ++index2;
            }
            while (index2 < this.treeGridView1.Nodes[0].Nodes.Count);
        }

        private void TimerSpoof_Tick(object sender, EventArgs e)
        {
            if (this.cArp == null || !this.cArp.HasRouter)
                return;
            this.timerSpoof.Interval = 5000;
            int index = 0;
            if (0 >= this.treeGridView1.Nodes[0].Nodes.Count)
                return;
            do
            {
                if (this.treeGridView1.Nodes[0].Nodes[index].Cells[8].Value.ToString().CompareTo("True") == 0)
                {
                    PC pcFromIp = this.pcs.getPCFromIP(tools.getIpAddress(this.treeGridView1.Nodes[0].Nodes[index].Cells[1].Value.ToString()).GetAddressBytes());
                    if (pcFromIp != null && !pcFromIp.isLocalPc && pcFromIp.canRedirect)
                        this.cArp.Spoof(pcFromIp.ip, new IPAddress(this.cArp.routerIP));
                }
                ++index;
            }
            while (index < this.treeGridView1.Nodes[0].Nodes.Count);
        }




        private void ViewMenuIP_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColPCIP.Visible = this.ViewMenuIP.Checked;
        }

        private void ViewMenuMAC_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColPCMac.Visible = this.ViewMenuMAC.Checked;
        }

        private void ViewMenuDownload_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColDownload.Visible = this.ViewMenuDownload.Checked;
        }

        private void ViewMenuUpload_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColUpload.Visible = this.ViewMenuUpload.Checked;
        }

        private void ViewMenuDownloadCap_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColDownCap.Visible = this.ViewMenuDownloadCap.Checked;
        }

        private void ViewMenuUploadCap_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColUploadCap.Visible = this.ViewMenuUploadCap.Checked;
        }



        private void ViewMenuBlock_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColBlock.Visible = this.ViewMenuBlock.Checked;
        }

        private void ViewMenuSpoof_CheckStateChanged(object sender, EventArgs e)
        {
            this.ColSpoof.Visible = this.ViewMenuSpoof.Checked;
        }

        private void SelfishNetTrayIcon_DoubleClick(object sender, EventArgs e)
        {

        }

        string[] args = Environment.GetCommandLineArgs();

        private void SelfishNetTrayIcon_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            Show();
            this.WindowState = FormWindowState.Normal;
        }

        private void ArpForm_Resize(object sender, EventArgs e)
        {
            AdjustAdvancedNetworkLayout();
            if (WindowState == FormWindowState.Minimized)
            {
                Hide();
            }
            else
            {

                if (first_start)
                {

                    CAdapter cadapter = new CAdapter();
                    this.cAdapter = cadapter;
                    cadapter.Show((IWin32Window)this);
                    first_start = false;
                }


            }
            //this.SelfishNetTrayIcon.ShowBalloonTip(2000);
        }

        private void ExitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
            //var rs = MessageBox.Show(this, "Quit?", "Quit", MessageBoxButtons.YesNo);
            //if (rs == DialogResult.Yes) Environment.Exit(0);
        }

        private void ShowToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Show();
            this.WindowState = FormWindowState.Normal;

        }

        private void ToolStripButton7_Click(object sender, EventArgs e)
        {
            WindowState = FormWindowState.Maximized;
        }


        private void ArpForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (!systemShutdown)
            {

                System.Windows.Forms.DialogResult result = MessageBox.Show("Are you sure you want to close the App?", "Application Closing!", MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
                switch (result)
                {
                    case System.Windows.Forms.DialogResult.OK:
                        if (WindowState == FormWindowState.Minimized)
                        {
                            Show();
                        }
                        ToolStripButton3_Click(toolStripButton3, new EventArgs());
                        SelfishNetTrayIcon.Dispose();
                        Environment.Exit(0);
                        break;
                }
                e.Cancel = true;
            }
            else
            {
                ToolStripButton3_Click(toolStripButton3, new EventArgs());
                SelfishNetTrayIcon.Dispose();
                Environment.Exit(0);

            }
            
        }

        private void ArpForm_Shown(object sender, EventArgs e)
        {
            string[] args = Environment.GetCommandLineArgs();
            if ((args.Length > 1))
            {
                minimized = true;
                if (args[1] == "minimize") this.WindowState = FormWindowState.Minimized;
            }
            Opacity = 100;
        }



        private static int WM_QUERYENDSESSION = 0x11;
        public static bool systemShutdown = false;
        protected override void WndProc(ref System.Windows.Forms.Message m)
        {
            if (m.Msg == WM_QUERYENDSESSION)
            {
                //MessageBox.Show("queryendsession: this is a logoff, shutdown, or reboot");
                systemShutdown = true;
            }

            // If this is WM_QUERYENDSESSION, the closing event should be  
            // raised in the base WndProc.  
            base.WndProc(ref m);

        } //WndProc   

#pragma warning restore  // Falta el comentario XML para el tipo o miembro visible públicamente
    }
}
