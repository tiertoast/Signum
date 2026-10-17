#pragma once
#include <podofo/podofo.h>
#include <string>
namespace signum {
using namespace PoDoFo;
inline void setTextAppearance(PdfMemDocument& doc, PdfSignature& signature,
                                const PoDoFo::Rect& rect, const std::string& holder) {
    if (rect.Width < 125 || rect.Height < 45)
        throw std::runtime_error("Visible signature rectangle too small");

    // The form XObject is a normal, pre-signing PDF object. It is never
    // appended to the signed PDF after the ByteRange has been calculated.
    auto appearance = doc.CreateXObjectForm(PoDoFo::Rect(0, 0, rect.Width, rect.Height));
    PdfPainter painter;
    painter.SetCanvas(*appearance);
    painter.GraphicsState.SetNonStrokingColor(PdfColor(1.0));
    painter.DrawRectangle(0, 0, rect.Width, rect.Height, PdfPathDrawMode::Fill);
    painter.GraphicsState.SetStrokingColor(PdfColor(0.45));
    painter.DrawRectangle(0.5, 0.5, rect.Width - 1, rect.Height - 1,
                          PdfPathDrawMode::Stroke);
    painter.GraphicsState.SetNonStrokingColor(PdfColor(0.1));
    auto& font = doc.GetFonts().GetStandard14Font(PdfStandard14FontType::Helvetica);
    painter.TextState.SetFont(font, 9);
    painter.DrawText("Firmato digitalmente da", 7, rect.Height - 17);
    painter.TextState.SetFont(font, 11);
    const auto truncated = holder.substr(0, 35);
    painter.DrawText(truncated, 7, rect.Height - 33);
    painter.FinishDrawing();

    signature.MustGetWidget().SetAppearanceStream(*appearance);
}

}
