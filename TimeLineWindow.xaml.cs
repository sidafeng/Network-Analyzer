using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Numerics;
using System.Reflection.Emit;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Network_Analyzer
{
    /// <summary>
    /// Interaction logic for TimeLineWindow.xaml
    /// </summary>
    public partial class TimeLineWindow : Window
    {
        
        internal TimeLineWindow()
        {
            InitializeComponent();
        }

        TimeLine timeline;
        private int packetCount;
        ObservableCollection<CapturedPacket> packets;
        internal TimeLineWindow(TimeLine timeline, ObservableCollection<CapturedPacket> packets, int packetCount)
        {
            InitializeComponent();
            this.timeline = timeline;
            this.packetCount = packetCount;
            this.packets = packets;
        }

        private void GraphCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            double height = GraphCanvas.ActualHeight;
            double width = GraphCanvas.ActualWidth;

            YAxis.X1 = 50;
            YAxis.Y1 = 20; //top of the graph
            YAxis.X2 = 50;
            YAxis.Y2 = height - 40; //bottom of the graph

            XAxis.X1 = 50;
            XAxis.Y1 = height - 40;
            XAxis.X2 = width - 20;
            XAxis.Y2 = height - 40;

            //clean the graph when resizing, GraphCanvas shifts indexes to the left after an item is removed.
            for (int i = GraphCanvas.Children.Count - 1; i >= 0; i--)
            {
                if (GraphCanvas.Children[i] is TextBlock || GraphCanvas.Children[i] is Ellipse || (GraphCanvas.Children[i] is Line &&
                    GraphCanvas.Children[i] != XAxis && GraphCanvas.Children[i] != YAxis))
                {
                    GraphCanvas.Children.RemoveAt(i);
                }
            }

            double xWidth = XAxis.X2 - XAxis.X1;
            double yHeight = YAxis.Y2 - YAxis.Y1;
            double ySpace = yHeight / 10;
            double xSpace = xWidth / 10;
            

            int[] interval = new int[10];
            
            for (int i = 0, j = 0; i < packetCount; i++)
            {
                if (packets[i].Timestamp <= (timeline.StartTime + (timeline.Interval * (j + 1))))
                {
                    interval[j]++;
                } else
                {
                    j++;
                    i--;
                }
            }

            int maxPacketCount = interval.Max();
            double packetSpace = (double)maxPacketCount / 10;

            double previousX = XAxis.X1;
            double previousY = YAxis.Y2;
            for (int i = 0; i < interval.Length; i++)
            {
                double x = XAxis.X1 + xSpace * (i + 1);
                double y = YAxis.Y2 - ((double)interval[i] / maxPacketCount * yHeight);
                Ellipse dot = new Ellipse();
                dot.Width = 6;
                dot.Height = 6;
                dot.Fill = Brushes.Cyan;
                Canvas.SetLeft(dot, x - 3);
                Canvas.SetTop(dot, y - 3);
                GraphCanvas.Children.Add(dot);
                Line line = new Line();
                line.X1 = previousX;
                line.Y1 = previousY;
                line.X2 = x;
                line.Y2 = y;
                line.Stroke = Brushes.Cyan;
                line.StrokeThickness = 2;
                GraphCanvas.Children.Add(line);
                previousX = x;
                previousY = y;
            }

 

            //get the time line blocks
            TextBlock tStart = new TextBlock();
            tStart.Text = timeline.StartTime.ToString("yyyy-MM-dd HH:mm:ss");
            tStart.Foreground = Brushes.White;
            Canvas.SetLeft(tStart, XAxis.X1 - 50);
            Canvas.SetTop(tStart, XAxis.Y1 + 5);
            GraphCanvas.Children.Add(tStart);

            for (int i = 1; i <= 10; i++)
            {
                TextBlock tLabel = new TextBlock();
                tLabel.Text = (timeline.StartTime + (timeline.Interval * i)).ToString("HH:mm:ss");
                tLabel.Foreground = Brushes.White;
                Canvas.SetLeft(tLabel, 25 + (xSpace * i));
                Canvas.SetTop(tLabel, XAxis.Y1 + 5);
                GraphCanvas.Children.Add(tLabel);
            }

            
            //get the vertical count blocks
            TextBlock pStart = new TextBlock();
            pStart.Width = 40;
            pStart.TextAlignment = TextAlignment.Right;
            pStart.Text = "0";
            pStart.Foreground = Brushes.White;
            Canvas.SetLeft(pStart, XAxis.X1 - 45);
            Canvas.SetTop(pStart, YAxis.Y2 - 10);
            GraphCanvas.Children.Add(pStart);

            
            for (int i = 1; i <= 10; i++)
            {
                TextBlock pLabel = new TextBlock();
                pLabel.Text = (packetSpace * i).ToString("F0");
                pLabel.Width = 40;
                pLabel.TextAlignment = TextAlignment.Right;
                pLabel.Foreground = Brushes.White;
                Canvas.SetLeft(pLabel, YAxis.X1 - 45);
                Canvas.SetTop(pLabel, YAxis.Y2 - (ySpace * i) - 10);
                GraphCanvas.Children.Add(pLabel);
            }

        }



    }
}
