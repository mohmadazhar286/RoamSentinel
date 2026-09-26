using Microsoft.Web.WebView2.Core;
using System.IO;
using System.Windows;

namespace RoamSentinel.Console;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += InitializeConsoleAsync;
    }

    private async void InitializeConsoleAsync(
        object sender,
        RoutedEventArgs eventArgs)
    {
        try
        {
            var userData = Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "RoamSentinel",
                "RS Console");
            Directory.CreateDirectory(userData);
            var environment = await CoreWebView2Environment.CreateAsync(
                userDataFolder: userData);
            await ConsoleView.EnsureCoreWebView2Async(environment);
            ConsoleView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            ConsoleView.CoreWebView2.Settings.AreDefaultContextMenusEnabled =
                false;
            ConsoleView.CoreWebView2.NavigationStarting += (_, args) =>
            {
                if (!args.Uri.StartsWith(
                        "http://127.0.0.1:5117/",
                        StringComparison.OrdinalIgnoreCase))
                {
                    args.Cancel = true;
                }
            };
            ConsoleView.Source = new Uri(
                "http://127.0.0.1:5117/?mode=desktop");
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                $"RS Agent is unavailable or the WebView2 runtime is missing.\n\n{exception.Message}",
                "RS Console",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }
}
