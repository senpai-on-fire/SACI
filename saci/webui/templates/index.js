function select_cpv(name)
{
    $.ajax({
        url: "/api/cpv_info",
        data: {
            name: name,
        },
        success: function(result) {
            $("#cpv-name").text("Selected CPV base: " + result["name"]);
            $("#components").html(gen_components_html(result["components"]));
            $("#search-btn").removeAttr("disabled");
        }
    });
}

function gen_components_html(components)
{
    var html = "";
    var i = 1;
    for (const comp of components) {
        html += '<div class="mb-3"><label class="form-label">Component ' + i + '</label>' +
            '<input type="text" class="form-control" value="' + comp["name"] + '" disabled>' +
            gen_component_abstraction_html(comp) +
            '</div>';
        // html += "-> <br />";
        i += 1;
    }
    // html += "<div>DONE</div>";
    return html;
}

function gen_component_abstraction_html(component)
{
    var html = "";
    if (!$.isEmptyObject(component["abstractions"])) {
        html = '<label class="form-label">Abstraction Level</label>' +
            '<select class="form-select">';
        for (var level in component["abstractions"]) {
            html += "<option>" + component["abstractions"][level] + "</option>";
        }
        html += "</select>";
    }
    return html;
}

function search_for_cpvs()
{
    $.ajax({
        url: "/api/cpv_search",
        data: {
            
        },
        success: function(result) {
            alert("Search ID: " + result["search_id"]);
        }
    });
}