#if os(macOS)
import Foundation
import CoreGraphics
import CoreText

struct ReportPDFLayout {
    struct Ink { let r: CGFloat,g: CGFloat,b: CGFloat
        var color: CGColor {CGColor(red:r,green:g,blue:b,alpha:1)}
        static let text=Ink(r:0.12,g:0.17,b:0.22), muted=Ink(r:0.34,g:0.39,b:0.44), accent=Ink(r:100.0/255,g:49.0/255,b:62.0/255)
    }
    struct Line { let text: NSAttributedString; let x,y,height: CGFloat; let ink: Ink }
    struct Box { let rect: CGRect; let ink: Ink }
    struct Page { var lines=[Line]();var boxes=[Box]();let section: String }
    static let width: CGFloat=595.28,height: CGFloat=841.89,margin: CGFloat=44,bottom: CGFloat=776
    var pages=[Page(section:"Sintesi della sessione")]
    var y: CGFloat=110
    var section="Sintesi della sessione"
    static func font(_ size: CGFloat,bold: Bool=false,mono: Bool=false) -> CTFont {
        let base=CTFontCreateUIFontForLanguage(mono ? .userFixedPitch:.system,size,nil) ?? CTFontCreateWithName("Helvetica" as CFString,size,nil)
        return bold ? (CTFontCreateCopyWithSymbolicTraits(base,size,nil,.boldTrait,.boldTrait) ?? base):base
    }
    static func attributed(_ text: String,size: CGFloat,bold: Bool=false,mono: Bool=false) -> NSAttributedString {
        NSAttributedString(string:text,attributes:[NSAttributedString.Key(kCTFontAttributeName as String):font(size,bold:bold,mono:mono),NSAttributedString.Key(kCTForegroundColorFromContextAttributeName as String):true])
    }
    static func wrapped(_ text: String,width: CGFloat,size: CGFloat,bold: Bool=false,mono: Bool=false) -> [NSAttributedString] {
        let value=attributed(text,size:size,bold:bold,mono:mono),setter=CTTypesetterCreateWithAttributedString(value)
        var result=[NSAttributedString](),offset=0
        while offset<value.length {
            var count=CTTypesetterSuggestLineBreak(setter,offset,Double(width))
            if count<=0 {count=CTTypesetterSuggestClusterBreak(setter,offset,Double(width))}
            if count<=0 {break}
            result.append(value.attributedSubstring(from:NSRange(location:offset,length:count)));offset+=count
        }
        return result
    }
    mutating func newPage() throws {
        guard pages.count<512 else {throw VerificationReportDocument.Failure.resourceLimit}
        pages.append(.init(section:section));y=110
    }
    mutating func ensure(_ height: CGFloat) throws {if y+height>Self.bottom {try newPage()}}
    mutating func paragraph(_ text: String,size: CGFloat=10,bold: Bool=false,ink: Ink = .text,after: CGFloat=7) throws {
        let height=ceil(size*1.5)
        let lines=Self.wrapped(text,width:Self.width-2*Self.margin,size:size,bold:bold)
        try ensure(min(CGFloat(lines.count),3)*height)
        for line in lines {
            try ensure(height);pages[pages.count-1].lines.append(.init(text:line,x:Self.margin,y:y,height:height,ink:ink));y+=height
        };y+=after
    }
    mutating func heading(_ text: String,size: CGFloat=15) throws {
        try ensure(65);try paragraph(text,size:size,bold:true,ink:.text,after:9)
    }
    mutating func field(_ key: String,_ value: String) throws {
        let labels=Self.wrapped(key,width:120,size:9,bold:true)
        let values=Self.wrapped(value,width:Self.width-2*Self.margin-156,size:key.contains("SHA-256") ? 9:10,mono:key.contains("SHA-256"))
        let rows=max(labels.count,values.count),height: CGFloat=15
        try ensure(min(CGFloat(rows),4)*height+7)
        for i in 0..<rows {
            try ensure(height)
            if i<labels.count {pages[pages.count-1].lines.append(.init(text:labels[i],x:Self.margin,y:y,height:height,ink:.accent))}
            if i<values.count {pages[pages.count-1].lines.append(.init(text:values[i],x:Self.margin+156,y:y,height:height,ink:.text))}
            y+=height
        };y+=7
    }
    mutating func summary(_ signer: VerificationReportDocument.Signer) throws {
        let title=signer.identity.count>140 ? String(signer.identity.prefix(140))+"…":signer.identity
        let titleLines=Self.wrapped("Firma \(signer.number) | "+title,width:Self.width-2*Self.margin-28,size:11,bold:true)
        let rows=signer.outcomes.map{ Self.wrapped($0.state,width:Self.width-2*Self.margin-160,size:9.5) }
        let height=CGFloat(titleLines.count)*17+CGFloat(rows.reduce(0){$0+max(1,$1.count)})*15+28
        try ensure(height+10)
        pages[pages.count-1].boxes.append(.init(rect:CGRect(x:Self.margin,y:y,width:Self.width-2*Self.margin,height:height),ink:.init(r:0.955,g:0.966,b:0.975)))
        pages[pages.count-1].boxes.append(.init(rect:CGRect(x:Self.margin,y:y,width:2,height:height),ink:.accent))
        y+=12
        for line in titleLines {pages[pages.count-1].lines.append(.init(text:line,x:Self.margin+14,y:y,height:17,ink:.text));y+=17}
        y+=5
        for (i,outcome) in signer.outcomes.enumerated() {
            pages[pages.count-1].lines.append(.init(text:Self.attributed(outcome.label,size:9),x:Self.margin+14,y:y,height:15,ink:.accent))
            for line in rows[i] {pages[pages.count-1].lines.append(.init(text:line,x:Self.margin+154,y:y,height:15,ink:.text));y+=15}
        };y+=11
    }
    init(_ document: VerificationReportDocument) throws {
        try paragraph("VERIFICA DELLE FIRME",size:9,bold:true,ink:.accent,after:9)
        try paragraph("Rapporto di verifica",size:29,bold:true,after:4)
        try paragraph("Esiti indipendenti. Evidenze e limiti della sessione.",size:10,ink:.muted,after:20)
        for field in document.fields {try self.field(field.label,field.value)}
        y+=8;try heading("Sintesi dei firmatari")
        if document.signers.isEmpty {try paragraph("Nessun risultato individuale disponibile. Consultare stato e motivazione del documento.")}
        for signer in document.signers {try summary(signer);y+=10}
        for signer in document.signers {
            section="Firma \(signer.number) | Dettagli";try newPage()
            try paragraph("FIRMA \(String(format:"%02d",signer.number))",size:9,bold:true,ink:.accent,after:7)
            try heading("Identità e oggetto della firma",size:21)
            for field in signer.fields {try self.field(field.label,field.value)}
            y+=9
            for (i,outcome) in signer.outcomes.enumerated() {
                try ensure(72)
                try paragraph("\(String(format:"%02d",i+1))  "+outcome.label.uppercased(),size:9,bold:true,ink:.accent,after:2)
                try paragraph(outcome.state,size:12,bold:true,after:3)
                try paragraph(outcome.reason,size:10,after:14)
            }
        }
        if document.signers.contains(where:{!$0.details.isEmpty}) {
            section="Evidenze e riferimenti del motore";try newPage();try heading("Riferimenti tecnici",size:24)
            for signer in document.signers where !signer.details.isEmpty {
                try heading("Firma \(String(format:"%02d",signer.number))",size:15)
                for field in signer.details {try self.field(field.label,field.value)}
                y+=12
            }
        }
        section="Perimetro e limiti";try newPage();try heading("Perimetro e limiti",size:24)
        for (i,note) in document.notes.enumerated() {try paragraph("\(i+1). "+note,size:10.5,after:13)}
        y+=10
        try field("Generato con","Signum "+document.productVersion)
        try field("Data di esportazione",VerificationReportDocument.date(document.exportedAt))
        try paragraph("Digital signatures. Simply native.",size:12,bold:true,ink:.accent,after:0)
    }
}

public enum VerificationReportPDF {
    public static let maximumBytes=32*1024*1024
    public static func data(_ document: VerificationReportDocument) throws -> Data {
        let layout=try ReportPDFLayout(document)
        let bytes=NSMutableData()
        guard let consumer=CGDataConsumer(data:bytes),let context=CGContext(consumer:consumer,mediaBox:nil,
            [kCGPDFContextTitle:"Rapporto di verifica Signum",kCGPDFContextAuthor:"Signum",kCGPDFContextCreator:"Signum "+document.productVersion] as CFDictionary) else {throw VerificationReportDocument.Failure.resourceLimit}
        func draw(_ text: NSAttributedString,x: CGFloat,y: CGFloat,ink: ReportPDFLayout.Ink) {
            let line=CTLineCreateWithAttributedString(text)
            var ascent: CGFloat=0;CTLineGetTypographicBounds(line,&ascent,nil,nil)
            context.setFillColor(ink.color);context.textMatrix = .identity
            context.textPosition=CGPoint(x:x,y:ReportPDFLayout.height-y-ascent);CTLineDraw(line,context)
        }
        for (i,page) in layout.pages.enumerated() {
            let rect=CGRect(x:0,y:0,width:ReportPDFLayout.width,height:ReportPDFLayout.height)
            context.beginPDFPage([kCGPDFContextMediaBox:Data(bytes:[rect],count:MemoryLayout<CGRect>.size)] as CFDictionary)
            context.setFillColor(CGColor(gray:1,alpha:1));context.fill(rect)
            context.setFillColor(ReportPDFLayout.Ink.accent.color);context.fill(CGRect(x:0,y:ReportPDFLayout.height-4,width:ReportPDFLayout.width,height:4))
            draw(ReportPDFLayout.attributed("SIGNUM",size:21,bold:true),x:44,y:31,ink:.text)
            draw(ReportPDFLayout.attributed("Digital signatures. Simply native.",size:8.5),x:44,y:59,ink:.accent)
            draw(ReportPDFLayout.attributed("RAPPORTO DI VERIFICA",size:8,bold:true),x:385,y:37,ink:.accent)
            draw(ReportPDFLayout.attributed(VerificationReportDocument.date(document.verificationDate),size:8),x:385,y:53,ink:.muted)
            context.setStrokeColor(ReportPDFLayout.Ink.accent.color);context.setLineWidth(0.5)
            context.move(to:CGPoint(x:44,y:759));context.addLine(to:CGPoint(x:551,y:759));context.strokePath()
            draw(ReportPDFLayout.attributed(page.section,size:8),x:44,y:88,ink:.muted)
            for box in page.boxes {
                context.setFillColor(box.ink.color);context.fill(CGRect(x:box.rect.minX,y:ReportPDFLayout.height-box.rect.maxY,width:box.rect.width,height:box.rect.height))
            }
            for line in page.lines {draw(line.text,x:line.x,y:line.y,ink:line.ink)}
            context.setStrokeColor(ReportPDFLayout.Ink.accent.color);context.move(to:CGPoint(x:44,y:46));context.addLine(to:CGPoint(x:551,y:46));context.strokePath()
            draw(ReportPDFLayout.attributed("SIGNUM  |  "+String(document.sha256.prefix(20)),size:8),x:44,y:806,ink:.muted)
            draw(ReportPDFLayout.attributed("\(i+1) / \(layout.pages.count)",size:8),x:510,y:806,ink:.muted)
            context.endPDFPage()
            guard bytes.length<=maximumBytes else {context.closePDF();throw VerificationReportDocument.Failure.resourceLimit}
        }
        context.closePDF()
        guard bytes.length<=maximumBytes else {throw VerificationReportDocument.Failure.resourceLimit}
        return bytes as Data
    }
}
#endif
