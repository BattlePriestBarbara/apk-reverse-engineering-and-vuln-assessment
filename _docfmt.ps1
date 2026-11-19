# 把 Word 可读 HTML 转成 .doc，并把表格列宽按内容比例铺满版心。
# 用法: powershell -File _docfmt.ps1 -In _report_tmp.html -Out 报告.doc
param(
    [Parameter(Mandatory = $true)][string]$In,
    [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0

try {
    $doc = $word.Documents.Open($In, $false, $false)

    $ps = $doc.PageSetup
    $ps.TopMargin = 48
    $ps.BottomMargin = 48
    $ps.LeftMargin = 48
    $ps.RightMargin = 48
    $textWidth = $ps.PageWidth - $ps.LeftMargin - $ps.RightMargin

    foreach ($t in $doc.Tables) {
        $ncol = $t.Columns.Count
        $nrow = [Math]::Min($t.Rows.Count, 12)

        # 每列显示宽度（中文按 2、ASCII 按 1）
        $maxw = @()
        for ($c = 0; $c -lt $ncol; $c++) { $maxw += 4.0 }
        for ($r = 1; $r -le $nrow; $r++) {
            for ($c = 1; $c -le $ncol; $c++) {
                try { $txt = $t.Cell($r, $c).Range.Text } catch { continue }
                $txt = $txt -replace "[`r`a]", ''
                $ascii = ([regex]::Matches($txt, '[\x20-\x7E]')).Count
                $w = ($txt.Length - $ascii) * 2 + $ascii
                if ($w -gt $maxw[$c - 1]) { $maxw[$c - 1] = [double]$w }
            }
        }

        $weights = @()
        foreach ($v in $maxw) {
            $x = [Math]::Min([Math]::Max($v, 5), 70)
            $weights += $x
        }
        $sum = ($weights | Measure-Object -Sum).Sum

        $t.AllowAutoFit = $false
        $t.PreferredWidthType = 3
        $t.PreferredWidth = $textWidth
        for ($c = 1; $c -le $ncol; $c++) {
            $wpt = [Math]::Round($textWidth * $weights[$c - 1] / $sum, 1)
            if ($wpt -lt 26) { $wpt = 26 }
            try { $t.Columns.Item($c).Width = $wpt } catch { }
        }

        if ($ncol -ge 5) { $t.Range.Font.Size = 7.5 } else { $t.Range.Font.Size = 8.5 }
        try { $t.Rows.AllowBreakAcrossPages = $false } catch { }
        try { if ($t.Rows.Count -gt 2) { $t.Rows.Item(1).HeadingFormat = $true } } catch { }
    }

    $doc.Content.ParagraphFormat.SpaceBefore = 0
    $doc.Content.ParagraphFormat.SpaceAfter = 2

    # 页脚：第 X 页 / 共 Y 页（wdFieldPage=33、wdFieldNumPages=26、wdFindStop=0）
    try {
        $sec = $doc.Sections.Item(1)
        $foot = $sec.Footers.Item(1)
        $base = $foot.Range
        $base.Text = '第 {PAGE} 页 / 共 {NUMPAGES} 页'
        $base.Font.Size = 8
        $base.ParagraphFormat.Alignment = 1
        foreach ($pair in @(@('{PAGE}', 33), @('{NUMPAGES}', 26))) {
            $rng = $foot.Range
            $find = $rng.Find
            $find.ClearFormatting()
            $find.Text = $pair[0]
            $find.Forward = $true
            $find.Wrap = 0
            if ($find.Execute()) { $doc.Fields.Add($rng, $pair[1]) | Out-Null }
        }
    }
    catch { "footer skipped: $($_.Exception.Message)" }

    $doc.Repaginate()
    $doc.SaveAs2($Out, 0)

    $pdf = [System.IO.Path]::ChangeExtension($Out, '.pdf')
    $doc.ExportAsFixedFormat($pdf, 17)

    $pages = $doc.ComputeStatistics(2)
    $words = $doc.ComputeStatistics(0)
    "doc=$Out pages=$pages words=$words tables=$($doc.Tables.Count)"
    $doc.Close(0)
}
finally {
    try { $word.Quit() } catch { }
}
