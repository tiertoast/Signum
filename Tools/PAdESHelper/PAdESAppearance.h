#pragma once
#include <podofo/podofo.h>
#include <string>
#include <cmath>
namespace signum {
using namespace PoDoFo;
// Explicit physical mode is used only by new GUI appearances. Legacy callers
// retain raw-unit limits. The actual immutable page value must match consent.
inline double approvedAppearanceUserUnit(const PdfPage& page, double expected) {
    double actual = 1;
    const auto* value = page.GetObject().GetDictionary().FindKey("UserUnit");
    if ((value && !value->TryGetReal(actual)) || !std::isfinite(actual) || actual <= 0 || actual > 75000 || actual != expected)
        throw std::runtime_error("Appearance UserUnit mismatch");
    return actual;
}
inline bool physicalAppearanceSize(double width, double height, double unit) {
    const double w = width * unit, h = height * unit;
    return std::isfinite(unit) && unit > 0 && unit <= 75000 && std::isfinite(w) && std::isfinite(h) &&
        ((w >= 80 && w <= 800 && h >= 40 && h <= 500) ||
         (h >= 80 && h <= 800 && w >= 40 && w <= 500));
}

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
