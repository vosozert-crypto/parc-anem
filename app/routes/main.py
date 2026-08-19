import os
from datetime import date

from flask import Blueprint, Response, render_template, request, session

from app import get_db
from app.routes.auth import login_required, admin_required
from app.routes.partage import _lignes_partage, _sites_partage

main_bp = Blueprint("main", __name__)

BAT_TEMPLATE = r"""@echo off
title Scan Reseau ANEM
color 0B
echo.
echo ========================================
echo   SCAN RESEAU ANEM
echo   Site: <<SITE>>
echo ========================================
echo.
echo Demarrage du scan...
echo.

powershell.exe -ExecutionPolicy Bypass -NoProfile -Command ^
 "$Url='<<URL>>';" ^
 "$Token='<<TOKEN>>';" ^
 "$Site='<<SITE>>';" ^
 "Write-Host '[ANEM] Reseau: 10.10.0.0/24' -ForegroundColor Cyan;" ^
 "$cidr='10.10.0.0/24';" ^
 "$parts=$cidr.Split('/');$netAddr=$parts[0];$prefixLen=[int]$parts[1];" ^
 "$ipParts=$netAddr.Split('.');" ^
 "$ipInt=[long]$ipParts[0]*16777216+[long]$ipParts[1]*65536+[long]$ipParts[2]*256+[long]$ipParts[3];" ^
 "$hostBits=32-$prefixLen;$totalHosts=[long][math]::Pow(2,$hostBits)-2;" ^
 "$machines=@();$imprimantes=@();$count=0;" ^
 "for($i=1;$i -le $totalHosts;$i++){" ^
 " $count++;$cur=$ipInt+$i;" ^
 " $a=[int]($cur/16777216) -band 255; $b=[int]($cur/65536) -band 255; $c=[int]($cur/256) -band 255; $d=$cur -band 255;" ^
 " $ip=[string]$a+'.'+[string]$b+'.'+[string]$c+'.'+[string]$d;" ^
 " $pct=[math]::Round($count/$totalHosts*100);" ^
 " Write-Progress -Activity 'Scan' -Status ('% '+$pct+' - '+$ip) -PercentComplete $pct;" ^
 " try{$ping=New-Object System.Net.NetworkInformation.Ping;$r=$ping.Send($ip,200);$ok=$r.Status -eq 'Success'}catch{$ok=$false};" ^
 " if($ok){" ^
 "  Write-Host '  [+] '+$ip -ForegroundColor Green;" ^
 "  try{$cs=Get-CimInstance Win32_ComputerSystem -ComputerName $ip -ErrorAction Stop;" ^
 "   $os=Get-CimInstance Win32_OperatingSystem -ComputerName $ip -ErrorAction Stop;" ^
 "   $pr=Get-CimInstance Win32_Processor -ComputerName $ip -ErrorAction Stop;" ^
 "   $bios=Get-CimInstance Win32_BIOS -ComputerName $ip -ErrorAction Stop;" ^
 "   $ram=[math]::Round($cs.TotalPhysicalMemory/1GB);" ^
 "   $machines+=[PSCustomObject]@{nom=$cs.Name;numero_serie=$bios.SerialNumber.Trim();marque_modele=($cs.Manufacturer+' '+$cs.Model);processeur=$pr.Name;ram_go=($ram.ToString()+' Go');arch=$os.OSArchitecture;generation='';disque='';user_session='';obs=''};" ^
 "   Write-Host '      -> '+$cs.Name+' | '+$cs.Manufacturer+' '+$cs.Model -ForegroundColor Gray" ^
 "  }catch{};" ^
 "  try{$printers=Get-CimInstance Win32_Printer -ComputerName $ip -ErrorAction Stop;" ^
 "   foreach($p in $printers){" ^
 "    if($p.PortName -and $p.PortName -notmatch '^USB'){" ^
 "     $imprimantes+=[PSCustomObject]@{nom=$p.Name;adresse_ip=$p.PortName;marque_modele=$p.DriverName;reference_toner='';stock_toner='';source_machine=$ip;remarques=''};" ^
 "     Write-Host '      -> Impr: '+$p.Name -ForegroundColor DarkYellow" ^
 "    }" ^
 "   }" ^
 "  }catch{}" ^
 " }" ^
 "};" ^
 "Write-Progress -Activity 'Scan' -Completed;" ^
 "Write-Host '';" ^
 "Write-Host '[ANEM] Detection des imprimantes USB locales...' -ForegroundColor Cyan;" ^
 "try{" ^
 "  $usbPrinters=Get-CimInstance Win32_Printer -ErrorAction Stop|Where-Object{$_.PortName -match '^USB'};" ^
 "  foreach($p in $usbPrinters){" ^
 "    $exists=$false;" ^
 "    foreach($e in $imprimantes){if($e.nom -eq $p.Name){$exists=$true;break}};" ^
 "    if(-not $exists){" ^
 "      $imprimantes+=[PSCustomObject]@{nom=$p.Name;adresse_ip=$p.PortName;marque_modele=$p.DriverName;reference_toner='';stock_toner='';source_machine='LOCAL';remarques='USB'};" ^
 "      Write-Host '  [USB] '+$p.Name+' ('+$p.PortName+')' -ForegroundColor Magenta" ^
 "    }" ^
 "  }" ^
 "}catch{};" ^
 "Write-Host '';" ^
 "Write-Host ('[ANEM] '+$machines.Count+' PC, '+$imprimantes.Count+' imprimantes (reseau+USB)') -ForegroundColor Cyan;" ^
 "$tryApi=$false;" ^
 "try{$test=Invoke-RestMethod -Uri ($Url+'/api/scan/status') -Headers @{Authorization='Bearer '+$Token} -TimeoutSec 5;$tryApi=$true}catch{};" ^
 "if($tryApi){" ^
 " Write-Host '[ANEM] Connexion OK, envoi a Railway...' -ForegroundColor Cyan;" ^
 " $body=$machines|ConvertTo-Json -Depth 5;" ^
 " try{$r=Invoke-RestMethod -Uri ($Url+'/api/scan/machines') -Method POST -Headers @{Authorization='Bearer '+$Token;'Content-Type'='application/json'} -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 60;Write-Host '  Machines: +'+$r.ajoutes+' ajoutes, '+$r.ignores+' ignores' -ForegroundColor Green}catch{Write-Host '  Erreur: '+$_.Exception.Message -ForegroundColor Red};" ^
 " $body2=$imprimantes|ConvertTo-Json -Depth 5;" ^
 " try{$r2=Invoke-RestMethod -Uri ($Url+'/api/scan/imprimantes') -Method POST -Headers @{Authorization='Bearer '+$Token;'Content-Type'='application/json'} -Body ([System.Text.Encoding]::UTF8.GetBytes($body2)) -TimeoutSec 60;Write-Host '  Imprimantes: +'+$r2.ajoutes+' ajoutes, '+$r2.ignores+' ignores' -ForegroundColor Green}catch{Write-Host '  Erreur: '+$_.Exception.Message -ForegroundColor Red};" ^
 " Write-Host '';" ^
 " Write-Host '[ANEM] TERMINE ! Donnees envoyees sur Railway.' -ForegroundColor Green;" ^
 " Write-Host '      Verifiez sur: $Url' -ForegroundColor Yellow" ^
 "}else{" ^
 " Write-Host '[ANEM] Pas de connexion internet.' -ForegroundColor Yellow;" ^
 " Write-Host '[ANEM] Generation des fichiers CSV...' -ForegroundColor Cyan;" ^
 " $ts=Get-Date -Format 'yyyyMMdd_HHmmss';" ^
 " $folder=Join-Path $env:USERPROFILE 'Desktop';" ^
 " if(-not(Test-Path $folder)){$folder=$env:TEMP};" ^
 " $siteName=$Site.Replace(' ','_');" ^
 " $fnPC='ANEM_PC_'+$siteName+'_'+$ts+'.csv';" ^
 " $fpPC=Join-Path $folder $fnPC;" ^
 " $sbPC=New-Object System.Text.StringBuilder;" ^
 " [void]$sbPC.AppendLine('nom,numero_serie,marque_modele,processeur,generation,ram_go,disque,arch,user_session,obs,site');" ^
 " foreach($m in $machines){" ^
 "  $line=@($m.nom,$m.numero_serie,$m.marque_modele,$m.processeur,$m.generation,$m.ram_go,$m.disque,$m.arch,$m.user_session,$m.obs,$Site)|ForEach-Object{(''+''''+($_ -replace '''','''''')+''''+'')};" ^
 "  [void]$sbPC.AppendLine($line -join ',');" ^
 " };" ^
 " [System.IO.File]::WriteAllText($fpPC,$sbPC.ToString(),[System.Text.Encoding]::UTF8);" ^
 " $fnImpr='ANEM_Imprimantes_'+$siteName+'_'+$ts+'.csv';" ^
 " $fpImpr=Join-Path $folder $fnImpr;" ^
 " $sbImpr=New-Object System.Text.StringBuilder;" ^
 " [void]$sbImpr.AppendLine('nom,adresse_ip,marque_modele,reference_toner,stock_toner,source_machine,remarques,site');" ^
 " foreach($p in $imprimantes){" ^
 "  $line=@($p.nom,$p.adresse_ip,$p.marque_modele,$p.reference_toner,$p.stock_toner,$p.source_machine,$p.remarques,$Site)|ForEach-Object{(''+''''+($_ -replace '''','''''')+''''+'')};" ^
 "  [void]$sbImpr.AppendLine($line -join ',');" ^
 " };" ^
 " [System.IO.File]::WriteAllText($fpImpr,$sbImpr.ToString(),[System.Text.Encoding]::UTF8);" ^
 " Write-Host '';" ^
 " Write-Host '[ANEM] PC: '+$fpPC -ForegroundColor Green;" ^
 " Write-Host '[ANEM] Imprimantes: '+$fpImpr -ForegroundColor Green;" ^
 " Write-Host '[ANEM] Importez-les sur le site via le bouton Import Excel.' -ForegroundColor Yellow;" ^
 " Write-Host '      $Url/scan' -ForegroundColor Yellow" ^
 "};" ^
 "Write-Host '';" ^
 "Write-Host 'Appuyez sur une touche pour fermer...' -ForegroundColor Gray;" ^
 "$null=$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')"

echo.
echo Scan termine !
pause
"""


@main_bp.route("/")
@login_required
def index():
    db = get_db()

    inventaire_par_type = db.execute(
        """
        SELECT marque_modele AS type, COUNT(*) AS total,
               GROUP_CONCAT(nom, ', ') AS details
        FROM machines
        GROUP BY marque_modele
        ORDER BY total DESC, marque_modele
        """
    ).fetchall()

    imprimantes_par_type = db.execute(
        """
        SELECT marque_modele AS type,
               COALESCE(NULLIF(reference_toner, ''), 'Non renseigne') AS ref,
               COUNT(*) AS total,
               GROUP_CONCAT(nom, ', ') AS details
        FROM imprimantes
        GROUP BY marque_modele, reference_toner
        ORDER BY total DESC, marque_modele, ref
        """
    ).fetchall()

    stock_faible = db.execute(
        """
        SELECT nom, marque_modele, reference_toner, stock_toner
        FROM imprimantes
        WHERE stock_toner IS NOT NULL AND stock_toner <= 2
        ORDER BY stock_toner
        """
    ).fetchall()

    is_admin = session.get("role") == "admin"

    stats = {
        "inventaire": {
            "total": sum(r["total"] for r in inventaire_par_type),
            "par_type": inventaire_par_type,
        },
        "imprimantes": {
            "total": sum(r["total"] for r in imprimantes_par_type),
            "par_type": imprimantes_par_type,
            "stock_faible": stock_faible,
        },
    }

    if is_admin:
        annee = date.today().year
        items_partage = _lignes_partage(annee)
        sites_partage = _sites_partage()
        totaux_sites = [
            sum(i["par_site"][j] for i in items_partage)
            for j in range(len(sites_partage))
        ]
        stats["partage"] = {
            "nb_items": len(items_partage),
            "nb_saisis": sum(
                1 for i in items_partage
                if i["qte_achetee"] or i["partage_total"] or i["total_sites"]
            ),
            "total_qte": sum(i["qte_achetee"] for i in items_partage),
            "total_partage": sum(i["partage_total"] for i in items_partage),
            "sites": sites_partage,
            "totaux_sites": totaux_sites,
            "total_sites": sum(totaux_sites),
            "lignes": items_partage,
        }

    return render_template(
        "index.html", nom=session.get("nom", ""), stats=stats, is_admin=is_admin,
    )


@main_bp.route("/scan")
@login_required
def scan_instructions():
    api_token = os.environ.get("API_TOKEN", "anem-scan-2026-secret")
    site_utilisateur = session.get("site", "")
    return render_template(
        "scan/instructions.html",
        api_token=api_token,
        site_utilisateur=site_utilisateur,
    )


@main_bp.route("/scan/telecharger")
@login_required
def telecharger_bat():
    api_token = os.environ.get("API_TOKEN", "anem-scan-2026-secret")
    site_utilisateur = session.get("site", "ANEM")

    host = request.host_url.rstrip("/")
    content = (
        BAT_TEMPLATE
        .replace("<<URL>>", host)
        .replace("<<TOKEN>>", api_token)
        .replace("<<SITE>>", site_utilisateur)
    )
    filename = "ANEM_Scan_{}.bat".format(site_utilisateur.replace(" ", "_"))
    return Response(
        content,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
