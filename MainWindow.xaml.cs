using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using IEplanPluginLicense.LicenseEngine;

namespace IEplanPluginLicense
{
    public partial class MainWindow : Window
    {
        // 预设默认密钥对（对应插件端默认集成的公钥），确保开箱即用
        private const string DefaultPrivateKeyXml = @"<RSAKeyValue><Modulus>6WmuAUbwFwnlJRNuoedojRHBY+h1HxQ1qbd+uof0PToEWaP/N3T8AW3VPhDDbDkXLG1AaNuh0C1d3Z6hKq93bzmUdpRasBYNJp7pm74yMVvaK6n2IU++v9Ho2LrSuAi0QFLcMczLRbz/VuHJ0MoZsYIrLZEv9E6xWTAptK+SxnvkY+qkY+PsOgtalv7hK9UylaujlzOIwjhXXgj5yb/iLLGcSoN4eUhqQhnJ8qdZNlT7YBDm+63mJS/B2V35GGzM8eP+7x9O7GqFvnQ1KzilTBbXuSIgxK5cuVrIrX5L4Ve24dWgei9JhfIbB7M4fFENp2GjYYJs18qFTZ8T64qULQ==</Modulus><Exponent>AQAB</Exponent><P>/0U0SaA3QI5GyjfLrGCw/4N81emOW79TmN5ZiXVHPdY2Q4VI04y3lejy9RZXe+TAAnbziIPDRVwUFq3Qm8g5p6KjLiLzHYlrVCmcwa0H5H/EyTmwa9mE0ZxUQm1wjqVKfO7OEiaikMnVeEHK82THkiSeBBafwb7hXt7DOxbi6aM=</P><Q>6hR7J8GgAtq+SXeYZPQeCjCRSRVoX6lSTJB6Dy/nJF4ysSDPKBPMBwN+zhRJx013/C+/lSPfEI0++3XzqjHV2GTXoVnxUr0/8EbzcsLbA3bsH42yxo7o5zffOcAoe0bdWVL41ole5QKiZ25by1fuTxyK7go1b+523LICeuRlB+8=</Q><DP>1GS/Ybc14be/vMd55r445xB/UPjYYwwpQVtYAmAbW58dXUbL1oERy2CcrkHdno8xF5vje6WuVsqLSGds2AFbv1g6D8wynlPVgpxw+lC+7WdF0+v1F3dP5Jv/G5o1eeqbtKF5wm50+qWEwV90vtkOmFFxTJOKb0kj+ay9oi+js6M=</DP><DQ>DeaxeabyDblX250Sm8wzjH9d4W04CZZQoONjnEtH+sztTb+ZDdQ/JZt7iFmEGCXtnjhntD+xG5aHyv8yPUVAYd17QMXKoxNCHM7Z3lLcFtSVKTqNB2WtRy32P8O9o7SNqKRYysTVsdv6MRJIuUa7jE8xoPlSOxd6T5jytMGjjlk=</DQ><InverseQ>th0LQ5nAOC7qb38iafsOOqK5+PopRx1sq4/7DPsRuQnLgxu9rYXtwneMtp1bJo6ZmVP9MKkUgV48jyZ0pwP4ShVYPCj3+IkCYdVOKJmmyC/ZXLKvdkM+7hc7KEx0braKbkS3KOU1woWx1VMr9TJJ7sXD2bS5fqqYkPDMyyYJJts=</InverseQ><D>qRWQIoaz18yoPRJ1mz1aRI7vLCOx7GCkexxc5l0kNdI4YoNll1PcVmCtD/fuyRAWVG2UMiGgd4DVtXx7PcO8Xks03C2eAF8JCcgmbFb8XzstsWG+1eTBxo0WAyJbEUvk34/myQCU5CEES3jmzKQKtscX5jt9pJn46SX1oFlrlvG4RHIcAkkPZdQJOy+vjhF9PerwqaOqEk/+zw05INdx/3cKUhY3a4QtRvagavfVrQceoF1rQcHaqzKz6na8BawK0uh9oV85+JGyie04Bn0W2a0sydzJKPT+hTrRtPhrrmUPcIMY6pIGBR+hq0ssyvtqz2YUKUkUSixedDp2TVzIFQ==</D></RSAKeyValue>";
        private const string DefaultPublicKeyXml = @"<RSAKeyValue><Modulus>6WmuAUbwFwnlJRNuoedojRHBY+h1HxQ1qbd+uof0PToEWaP/N3T8AW3VPhDDbDkXLG1AaNuh0C1d3Z6hKq93bzmUdpRasBYNJp7pm74yMVvaK6n2IU++v9Ho2LrSuAi0QFLcMczLRbz/VuHJ0MoZsYIrLZEv9E6xWTAptK+SxnvkY+qkY+PsOgtalv7hK9UylaujlzOIwjhXXgj5yb/iLLGcSoN4eUhqQhnJ8qdZNlT7YBDm+63mJS/B2V35GGzM8eP+7x9O7GqFvnQ1KzilTBbXuSIgxK5cuVrIrX5L4Ve24dWgei9JhfIbB7M4fFENp2GjYYJs18qFTZ8T64qULQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public MainWindow()
        {
            InitializeComponent();

            // 1. 默认填充开发测试的公私钥对
            TxtDevPrivateKey.Text = DefaultPrivateKeyXml;
            TxtDevPublicKey.Text = DefaultPublicKeyXml;

            // 2. 目标机器码默认留空，等待填入客户真实的机器码
            TxtInputMachineCode.Text = string.Empty;
            DpInputDate.SelectedDate = DateTime.Now.AddYears(1);
        }

        private void UnlockKeys_Click(object sender, RoutedEventArgs e)
        {
            if (TxtDevPrivateKey.IsReadOnly)
            {
                TxtDevPrivateKey.IsReadOnly = false;
                TxtDevPublicKey.IsReadOnly = false;
                BtnUnlockKeys.Content = "🔒 锁定密钥编辑";
                BtnUnlockKeys.Background = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF2E63"));
            }
            else
            {
                TxtDevPrivateKey.IsReadOnly = true;
                TxtDevPublicKey.IsReadOnly = true;
                BtnUnlockKeys.Content = "🔓 解锁密钥编辑";
                BtnUnlockKeys.Background = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#2D2D37"));
            }
        }

        // ======================= 密钥对管理 =======================

        private void GenerateKeys_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var (priv, pub) = LicenseGenerator.GenerateKeyPair();
                TxtDevPrivateKey.Text = priv;
                TxtDevPublicKey.Text = pub;
                MessageBox.Show("已成功生成全新 RSA-2048 密钥对！\n生产发布时，请务必将生成的【新公钥】拷贝并替换到插件的 LicenseVerifier.cs 中。", "密钥生成成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成密钥对失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CopyPublicKey_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtDevPublicKey.Text))
            {
                MessageBox.Show("公钥内容为空，无法复制。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                Clipboard.SetText(TxtDevPublicKey.Text.Trim());
                MessageBox.Show("公钥已成功复制到剪贴板！\n请打开插件项目，将其粘贴并硬编码替换至 LicenseVerifier.cs 的 DefaultPublicKeyXml 常量中。", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"复制失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveKeysToFile_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtDevPrivateKey.Text) || string.IsNullOrWhiteSpace(TxtDevPublicKey.Text))
            {
                MessageBox.Show("当前密钥文本为空，请先导入或生成密钥对。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var saveFileDialog = new SaveFileDialog
            {
                Filter = "XML 密钥文件 (*.xml)|*.xml",
                FileName = "PrivateKey.xml",
                Title = "保存私钥 (公钥将同步保存在同目录下)"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(saveFileDialog.FileName, TxtDevPrivateKey.Text.Trim());
                    string dir = Path.GetDirectoryName(saveFileDialog.FileName) ?? AppDomain.CurrentDomain.BaseDirectory;
                    string pubPath = Path.Combine(dir, "PublicKey.xml");
                    File.WriteAllText(pubPath, TxtDevPublicKey.Text.Trim());

                    MessageBox.Show($"密钥保存成功！\n\n私钥路径: {saveFileDialog.FileName}\n公钥路径: {pubPath}\n\n提醒：私钥文件请严格保密，公钥文件用于嵌入插件代码。", "保存成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"保存密钥失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void LoadKeysFromFile_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "XML 密钥文件 (*.xml)|*.xml",
                Title = "选择要载入的私钥/密钥对文件"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    string content = File.ReadAllText(openFileDialog.FileName).Trim();
                    
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.FromXmlString(content);
                        if (rsa.PublicOnly)
                        {
                            TxtDevPublicKey.Text = content;
                            TxtDevPrivateKey.Text = string.Empty;
                            MessageBox.Show("您导入的是【公钥】文件。生成授权（签名）必须依赖【私钥】，发卡功能当前不可用，建议导入包含私钥的密钥文件。", "导入提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                        else
                        {
                            TxtDevPrivateKey.Text = content;
                            string publicKeyXml = rsa.ToXmlString(false);
                            TxtDevPublicKey.Text = publicKeyXml;
                            MessageBox.Show("私钥导入成功，并已自动为您导出匹配的公钥！", "导入成功", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导入密钥失败，请确保选择的文件是合法的 XML 密钥格式: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // ======================= 签发授权 =======================

        private void FillLocalMachineCode_Click(object sender, RoutedEventArgs e)
        {
            TxtInputMachineCode.Text = HardwareFingerprint.GetMachineCode();
        }

        private void GenerateLicense_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtDevPrivateKey.Text))
            {
                MessageBox.Show("当前私钥为空，无法进行加密签名！请先生成或导入私钥。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrWhiteSpace(TxtInputMachineCode.Text))
            {
                MessageBox.Show("请输入目标客户端电脑的机器码！\n您也可以点击“填入本机机器码”获取本机特征以供测试。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrWhiteSpace(TxtInputUser.Text))
            {
                MessageBox.Show("请输入被授权的用户名或单位名称！", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (DpInputDate.SelectedDate == null)
            {
                MessageBox.Show("请选择授权的截止到期时间！", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                var licInfo = new LicenseInfo
                {
                    MachineCode = TxtInputMachineCode.Text.Trim(),
                    UserName = TxtInputUser.Text.Trim(),
                    ExpireDate = DpInputDate.SelectedDate.Value.ToString("yyyy-MM-dd")
                };

                // 生成签名后的许可证内容
                string licenseContent = LicenseGenerator.GenerateLicense(licInfo, TxtDevPrivateKey.Text.Trim());

                // 弹出保存文件对话框
                var saveFileDialog = new SaveFileDialog
                {
                    Filter = "授权文件 (*.lic)|*.lic",
                    FileName = "license.lic",
                    Title = "保存签发的授权证书文件"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    File.WriteAllText(saveFileDialog.FileName, licenseContent);
                    MessageBox.Show($"授权证书已成功生成并导出！\n\n文件路径: {saveFileDialog.FileName}\n\n请将该授权文件发给客户，指导其导入或直接放置在插件 DLL 的同级目录下即可激活插件使用。", "发卡成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成授权文件失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}