#include "MainFrame.h"
#include <wx/wx.h>
#include <wx/notebook.h>
#include <nlohmann/json.hpp>

#include "MainFrame.h"

using namespace std;
using json = nlohmann::json;

class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title, const json& data);
};

MainFrame::MainFrame(const wxString& title, const json& data)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600))
{
    wxNotebook* notebook = new wxNotebook(this, wxID_ANY);

    for (const auto& group : data["groups"]) {
        wxString groupName = wxString::FromUTF8(group["name"].get<std::string>());
        wxPanel* panel = new wxPanel(notebook);

        // Create a listbox with messages
        wxArrayString messages;
        for (const auto& message : group["messages"]) {
            wxString msg = wxString::FromUTF8(message.get<std::string>());
            messages.Add(msg);
        }

        wxListBox* listBox = new wxListBox(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize,
            messages, wxLB_SINGLE);

        wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
        sizer->Add(listBox, 1, wxEXPAND | wxALL, 5);
        panel->SetSizer(sizer);

        notebook->AddPage(panel, groupName);
    }

    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    mainSizer->Add(notebook, 1, wxEXPAND | wxALL, 5);
    SetSizer(mainSizer);
}