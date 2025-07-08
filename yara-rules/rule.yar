rule malware1{
	strings:
		$s1 = "QpSl.exe"
		$s2 = "MeasureExecutionTime"
		$s3 = "System.Resources.ResourceReader"
		$s4 = "System.Resources.Forms"
		$s5 = "System.Reflection.Assembly"
		$s5 = "mscoree.dll"
	condition:
		all of them
}
