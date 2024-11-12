function select_cpv(name)
{
    $.ajax({
        url: "/api/cpv_info",
        data: {
            name: name,
        },
        success: function(result) {
            $("#cpv-name").text(result["name"]);
            $("#cpv-name").attr("cpv-class-name", result["cls_name"]);
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
            '<div class="row">' +
            '<div class="col"><input type="text" class="form-control" value="' + comp["name"] + '" disabled></div>' +
            '<div class="col">' +
            gen_component_abstraction_html(comp) + '</div>' +
            '</div></div>';
        // html += "-> <br />";
        i += 1;
    }
    // html += "<div>DONE</div>";
    return html;
}

function get_blueprint_component_graph(blueprint_id)
{
    $("#blueprint_graph").empty();
    $("#blueprint_options").empty();
    $.ajax({
        url: "/api/get_blueprint",
        data: {
            "id": blueprint_id,
        },
        success: function (result) {
            if (result["error"] !== undefined) {
                console.log(data["error"]);
                return;
            }

            const data = result["component_graph"];

            const width = 1400;
            const height = 300;

            const svg = d3.select("#blueprint_graph")
                .append("svg")
                .attr("width", width)
                .attr("height", height);

            const color = d3.scaleOrdinal(d3.schemeCategory10);

            // Position each node randomly, should probably use an actual graph layout algo!
            data.nodes.forEach((node, index) => {
                node.x = 50 + Math.random() * 600;
                node.y = 50 + Math.random() * 250;
            });

            const link = svg.append("g")
                .attr("class", "links")
                .selectAll("line")
                .data(data.links)
                .enter().append("line")
                .attr("class", "link")
                .attr("stroke-width", 2)
                .attr("stroke", "#999");

            const node = svg.append("g")
                .attr("class", "nodes")
                .selectAll("circle")
                .data(data.nodes)
                .enter().append("circle")
                .attr("r", 10)
                .attr("fill", d => color(d.id));

            const text = svg.append("g")
                .attr("class", "texts")
                .selectAll("text")
                .data(data.nodes)
                .enter().append("text")
                .attr("dy", -30)
                .attr("text-anchor", "middle")
                .text(d => d.name);

            link.attr("x1", d => data.nodes.find(node => node.id === d.source).x)
                .attr("y1", d => data.nodes.find(node => node.id === d.source).y)
                .attr("x2", d => data.nodes.find(node => node.id === d.target).x)
                .attr("y2", d => data.nodes.find(node => node.id === d.target).y);

            // Set node positions based on manually set node positions
            node.attr("cx", d => d.x)
                .attr("cy", d => d.y);

            // Set text positions based on manually set node positions
            text.attr("x", d => d.x)
                .attr("y", d => d.y);

            const blueprint_options = $("#blueprint_options");
            console.log(data.options);
            for (const [option, value] of Object.entries(data.options)) {
                const option_div = $("<div></div>").text(`${option}:`);
                const input = $("<input>");
                input.attr("type", "text");
                input.val(`${value}`);
                option_div.append(input);
                blueprint_options.append(option_div);
                input.on("change", event => {
                    console.log(input.val());
                    event.preventDefault();
                    $.post({
                        url: `/api/set_blueprint_option?id=${blueprint_id}&option=${option}`,
                        data: input.val(),
                        contentType: "application/json",
                    });
                });
            }
        }
    });
}

function gen_component_abstraction_html(component)
{
    var html = "";
    if (!$.isEmptyObject(component["abstractions"])) {
        html = // '<label class="form-label">Abstraction Level</label>' +
            '<select class="form-select">';
        for (var level in component["abstractions"]) {
            if (component["abstractions"][level] == "-") {
                html += "<option selected>" + component["abstractions"][level] + "</option>";
            } else {
                html += "<option>" + component["abstractions"][level] + "</option>";
            }
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
            cpv_name: $("#cpv-name").attr("cpv-class-name"),
            blueprint_id: $('#blueprint').find('option:selected').val()
        },
        success: function(result) {
            // alert("Search ID: " + result["search_id"]);
        }
    });
}

function get_cpv_research_result_html(search_id, r)
{
    var container = $("<div><h4>Search " + search_id + "</h4></div>");
    var json_code = $('<code id="code" name="code" class="language-json" style="overflow-wrap: anywhere;" readonly></code>').html(
        hljs.highlight(JSON.stringify(r, null, 4), {'language': 'json'}).value
    );
    var json_pre = $('<pre class="code" style="background-color: #f3f3f3;"></pre>').append(json_code);
    container.append(json_pre);
    if (r["cpv_inputs"] !== "None") {
        var cpv = $("<div></div>").text(r["cpv_inputs"][0][0]);
        var cpv_path = $("<div></div>").text(r["cpv_inputs"][0][1]);
        var input = $("<div></div>").text(r["cpv_inputs"][0][2]);

        container.append(cpv);
        container.append(cpv_path);
        container.append(input);
    }
    return container;
}

function update_cpv_search_results()
{
    var cpv_search_ids = null;
    $.ajax({
        url: "/api/cpv_search_ids",
        success: function(result) {
            cpv_search_ids = result["ids"];

            if (!cpv_search_ids.length) {
                $("#cpv-search-results").html("<span id='no-search'>No running searches.</span>");
                return;
            } else {
                $("#no-search").remove();
            }

            for (const cpv_search_id of cpv_search_ids) {
                $.ajax({
                    url: "/api/cpv_search_result",
                    data: {
                        id: cpv_search_id,
                    },
                    success: function (result) {
                        var should_update = false;
                        var elem_id = "cpv-search-result-" + cpv_search_id;
                        if (!$("#" + elem_id).length) {
                            // create the element
                            $("#cpv-search-results").append($('<div id="' + elem_id + '">Test</div>'));
                            should_update = true;
                        } else {
                            if (result["last_updated"].toString() !== $("#" + elem_id).attr("last_updated")) {
                                should_update = true;
                            }
                        }
                        if (should_update) {
                            $("#" + elem_id).html(get_cpv_research_result_html(cpv_search_id, result));
                            $("#" + elem_id).attr("last_updated", result["last_updated"]);
                        }
                    }
                });
            }
        }
    });
}

function add_blueprint() {
    const name = $("#new-blueprint-name").val();
    const blueprint = $("#new-blueprint-json").val();
    $.post({
        url: "/api/ingest_blueprint?name=" + encodeURIComponent(name),
        data: blueprint,
        contentType: "application/json",
        success: () => {
            alert(`added blueprint ${name} successfully`);
        },
        error: (xhr) => {
            alert(`adding blueprint failed: ${xhr.responseText}`);
        },
    })
}

$(document).ready(function() {
    setInterval(update_cpv_search_results, 1000);
});
