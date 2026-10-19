import AppKit
import Foundation

let destination = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
func draw(size: Int, name: String) throws {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    let context = NSGraphicsContext(bitmapImageRep: bitmap)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = context
    let scale = CGFloat(size) / 1024
    let transform = NSAffineTransform(); transform.scale(by: scale); transform.concat()
    NSColor(calibratedRed: 0.94, green: 0.92, blue: 0.87, alpha: 1).setFill()
    let plate = NSBezierPath(roundedRect: NSRect(x: 76, y: 76, width: 872, height: 872), xRadius: 200, yRadius: 200)
    let shadow = NSShadow(); shadow.shadowColor = NSColor.black.withAlphaComponent(0.15); shadow.shadowBlurRadius = 18; shadow.shadowOffset = NSSize(width: 0, height: -8); shadow.set(); plate.fill()
    NSShadow().set()
    NSColor(calibratedRed: 0.14, green: 0.22, blue: 0.18, alpha: 1).setStroke()
    let cloud = NSBezierPath(); cloud.move(to: NSPoint(x: 310, y: 360)); cloud.line(to: NSPoint(x: 720, y: 360))
    cloud.curve(to: NSPoint(x: 740, y: 600), controlPoint1: NSPoint(x: 870, y: 360), controlPoint2: NSPoint(x: 880, y: 595))
    cloud.curve(to: NSPoint(x: 355, y: 640), controlPoint1: NSPoint(x: 700, y: 815), controlPoint2: NSPoint(x: 415, y: 830))
    cloud.curve(to: NSPoint(x: 310, y: 360), controlPoint1: NSPoint(x: 120, y: 620), controlPoint2: NSPoint(x: 150, y: 360))
    cloud.lineWidth = 29; cloud.lineCapStyle = .round; cloud.lineJoinStyle = .round; cloud.stroke()
    NSColor(calibratedRed: 0.78, green: 0.35, blue: 0.23, alpha: 1).setFill()
    NSBezierPath(ovalIn: NSRect(x: 467, y: 235, width: 90, height: 90)).fill()
    NSGraphicsContext.restoreGraphicsState()
    try bitmap.representation(using: .png, properties: [:])!.write(to: destination.appendingPathComponent(name))
}
for size in [16,32,128,256,512] {
    try draw(size: size, name: "icon_\(size)x\(size).png")
    try draw(size: size * 2, name: "icon_\(size)x\(size)@2x.png")
}
