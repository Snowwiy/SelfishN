using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Windows.Forms;

namespace SelfishNetv3
{
#pragma warning disable  // Falta el comentario XML para el tipo o miembro visible publicamente
    public partial class CAdapter : Form
    {
        private NetworkInterface[] nics;

        private List<NetworkInterface> visibleNics;

        public NetworkInterface selectedNic;

        public bool packetsHaveToBeRedirected;
        public CAdapter()
        {
            InitializeComponent();
            nics = NetworkInterface.GetAllNetworkInterfaces();
            visibleNics = new List<NetworkInterface>();
            buttonOK.Enabled = false;
            packetsHaveToBeRedirected = false;
            buttonCancel.Text = "Quit";
        }

        private void ComboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (comboBox1.SelectedIndex < 0 || comboBox1.SelectedIndex >= visibleNics.Count)
            {
                return;
            }

            NetworkInterface networkInterface = visibleNics[comboBox1.SelectedIndex];
            labelTypeText.Text = ((NetworkInterfaceType)(object)networkInterface.NetworkInterfaceType).ToString();
            labelIpText.Text = GetPrimaryIPv4(networkInterface);
            IPAddress gateway = GetPrimaryGateway(networkInterface);
            labelGWText.Text = gateway == null ? "No Gateway - discovery only" : gateway.ToString();

            selectedNic = networkInterface;
            buttonOK.Enabled = HasIPv4(networkInterface);
            UpdateRedirectInfo(networkInterface);
        }

        private void ButtonCancel_Click(object sender, EventArgs e)
        {


            if (!ArpForm.systemShutdown)
            {

                System.Windows.Forms.DialogResult result = MessageBox.Show("Are you sure you want to close the App?", "Application Closing!", MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
                switch (result)
                {
                    case System.Windows.Forms.DialogResult.OK:
                        if (WindowState == FormWindowState.Minimized)
                        {
                            Show();
                        }
                        if (buttonCancel.Text.CompareTo("Quit") == 0)
                        {
                            ((IDisposable)ArpForm.instance).Dispose();
                            return;
                        }
                        ArpForm.instance.Enabled = true;
                        Close();
                        break;
                }

            }
            else
            {
                if (buttonCancel.Text.CompareTo("Quit") == 0)
                {
                    ((IDisposable)ArpForm.instance).Dispose();
                    return;
                }
                ArpForm.instance.Enabled = true;
                Close();

            }
        }

        private void ButtonOK_Click(object sender, EventArgs e)
        {
            buttonCancel.Text = "Cancel";
            ArpForm.instance.Enabled = true;
            ArpForm.instance.NicIsSelected(selectedNic);
            Close();
        }

        private void CAdapter_Shown(object sender, EventArgs e)
        {
            Opacity = 100;
            ArpForm.instance.Enabled = false;
            RefreshAdapterList();
        }

        private void RefreshAdapterList()
        {
            nics = NetworkInterface.GetAllNetworkInterfaces();
            visibleNics.Clear();
            comboBox1.Items.Clear();

            foreach (NetworkInterface networkInterface in nics)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up && HasIPv4(networkInterface))
                {
                    visibleNics.Add(networkInterface);
                    comboBox1.Items.Add(BuildDisplayName(networkInterface));
                }
            }

            if (comboBox1.Items.Count == 0)
            {
                MessageBox.Show("No active IPv4 network adapter has been found!");
                ((IDisposable)ArpForm.instance).Dispose();
                return;
            }

            int selectedIndex = 0;
            for (int i = 0; i < visibleNics.Count; i++)
            {
                if (GetPrimaryGateway(visibleNics[i]) != null)
                {
                    selectedIndex = i;
                    break;
                }
            }

            comboBox1.SelectedIndex = selectedIndex;
        }

        private static bool HasIPv4(NetworkInterface networkInterface)
        {
            foreach (UnicastIPAddressInformation address in networkInterface.GetIPProperties().UnicastAddresses)
            {
                if (address.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    return true;
                }
            }
            return false;
        }

        private static string GetPrimaryIPv4(NetworkInterface networkInterface)
        {
            foreach (UnicastIPAddressInformation address in networkInterface.GetIPProperties().UnicastAddresses)
            {
                if (address.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    return address.Address.ToString();
                }
            }
            return "0.0.0.0";
        }

        private static IPAddress GetPrimaryGateway(NetworkInterface networkInterface)
        {
            foreach (GatewayIPAddressInformation gateway in networkInterface.GetIPProperties().GatewayAddresses)
            {
                if (gateway.Address.AddressFamily == AddressFamily.InterNetwork && gateway.Address.ToString().CompareTo("0.0.0.0") != 0)
                {
                    return gateway.Address;
                }
            }
            return null;
        }

        private static string BuildDisplayName(NetworkInterface networkInterface)
        {
            IPAddress gateway = GetPrimaryGateway(networkInterface);
            string gatewayText = gateway == null ? "no gateway" : "gw " + gateway.ToString();
            return networkInterface.Description + " (" + GetPrimaryIPv4(networkInterface) + ", " + gatewayText + ")";
        }

        private void UpdateRedirectInfo(NetworkInterface networkInterface)
        {
            try
            {
                IPv4InterfaceProperties properties = networkInterface.GetIPProperties().GetIPv4Properties();
                if (properties != null && properties.IsForwardingEnabled)
                {
                    labelRedirectInfo.Text = "Windows does redirect packet,\n internal redirection will be turned off";
                    packetsHaveToBeRedirected = false;
                }
                else
                {
                    labelRedirectInfo.Text = "Windows does not redirect packet,\n internal redirection will be turned on";
                    packetsHaveToBeRedirected = true;
                }
            }
            catch
            {
                labelRedirectInfo.Text = "Unable to read Windows forwarding status";
                packetsHaveToBeRedirected = true;
            }
        }
    }
#pragma warning restore  // Falta el comentario XML para el tipo o miembro visible publicamente
}
