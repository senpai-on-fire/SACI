import {
  CurveFactory,
  Edge,
  GeomEdge,
  GeomGraph,
  GeomNode,
  Graph,
  Node,
  Point,
  layoutGeomGraph,
} from 'https://cdn.jsdelivr.net/npm/@msagl/core@1.1.23/+esm';

// Mock data for CPVs and their details
const cpvs_blueprint_1 = [
    { id: 1, name: "CPV 1", details: ["Entry Component", "Required Component", "Associated CPS", "Initial System State", "Attack Vector", "Attack Impact", "Attack Requirements", "Privileges Requirements", "User-System Interactions", "Attack Steps"] },
    { id: 2, name: "CPV 2", details: ["Entry Component 2", "Required Component 2", "Associated CPS 2", "Initial System State 2", "Attack Vector 2", "Attack Impact 2", "Attack Requirements 2", "Privileges Requirements 2", "User-System Interactions 2", "Attack Steps 2"] },
];

const cpvs_blueprint_2 = [
    { id: 1, name: "CPV 1", details: ["Entry Component", "Required Component", "Associated CPS", "Initial System State", "Attack Vector", "Attack Impact", "Attack Requirements", "Privileges Requirements", "User-System Interactions", "Attack Steps"] },
    { id: 2, name: "CPV 2", details: ["Entry Component 2", "Required Component 2", "Associated CPS 2", "Initial System State 2", "Attack Vector 2", "Attack Impact 2", "Attack Requirements 2", "Privileges Requirements 2", "User-System Interactions 2", "Attack Steps 2"] },
];

let autoUpdateEnabled = true;
let currentCPVId = null;
let autoUpdatePaused = false;
let selectedBlueprintId = null;

// Initialize blueprint selection handler
function initializeBlueprintSelection() {
    const blueprintSelect = document.getElementById("blueprint");
    if (blueprintSelect) {
        // Set initial value
        selectedBlueprintId = blueprintSelect.value;
        
        // Add change event listener
        blueprintSelect.addEventListener('change', function(e) {
            selectedBlueprintId = e.target.value;
            clearSearchResults();
            updateSearchButtonState();
            get_blueprint_component_graph(selectedBlueprintId);
        });
    }
}

// Clear search results and details
function clearSearchResults() {
    const cpvResultsDiv = document.getElementById("cpv-search-results");
    const cpvDetailsDiv = document.getElementById("cpv-detail-results");
    
    if (cpvResultsDiv) {
        cpvResultsDiv.innerHTML = '<div class="alert alert-info">Select a blueprint and click Search to find relevant CPVs.</div>';
    }
    
    if (cpvDetailsDiv) {
        cpvDetailsDiv.innerHTML = '';
    }
    
    currentCPVId = null;
}

// Update search button state based on blueprint selection
function updateSearchButtonState() {
    const searchBtn = document.getElementById("search-btn");
    if (searchBtn) {
        if (selectedBlueprintId) {
            searchBtn.removeAttribute('disabled');
            searchBtn.title = 'Click to search for CPVs';
        } else {
            searchBtn.setAttribute('disabled', 'disabled');
            searchBtn.title = 'Please select a blueprint first';
        }
    }
}

// Search for CPVs with selected blueprint
function searchForCPVs() {
    if (!selectedBlueprintId) {
        console.error("No blueprint selected");
        return;
    }

    console.log(`Searching CPVs for blueprint: ${selectedBlueprintId}`);

    autoUpdatePaused = true;
    setTimeout(() => {
        autoUpdatePaused = false;
    }, 10000);

    const cpvResultsDiv = document.getElementById("cpv-search-results");
    if (!cpvResultsDiv) {
        console.error("CPV results container not found");
        return;
    }

    // Show loading state
    cpvResultsDiv.innerHTML = '<div class="alert alert-info">Searching CPVs...</div>';

    // Filter or fetch CPVs based on selected blueprint
    // This is where you would typically make an API call to get CPVs for the selected blueprint
    // For now, we'll use the mock data
    const table = document.createElement("table");
    table.className = "table table-bordered";
    const thead = document.createElement("thead");
    thead.innerHTML = "<tr><th>CPV ID</th><th>CPV Name</th><th>Blueprint</th></tr>";
    table.appendChild(thead);

    const tbody = document.createElement("tbody");

    cpvs_blueprint_1.forEach((cpv) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${cpv.id}</td>
            <td><button class="btn btn-link" onclick="showCPVDetails(${cpv.id});">${cpv.name}</button></td>
            <td>Blueprint ${selectedBlueprintId}</td>
        `;
        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    cpvResultsDiv.innerHTML = '';
    cpvResultsDiv.appendChild(table);
}
// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    initializeBlueprintSelection();
    updateSearchButtonState();
    clearSearchResults();
});
window.searchForCPVs = searchForCPVs;

// Show details for selected CPV
function showCPVDetails(cpvId) {
    console.log(`Displaying details for CPV ID: ${cpvId}`);
    currentCPVId = cpvId;

    const selectedCPV = cpvs_blueprint_1.find(cpv => cpv.id === cpvId);
    const cpvDetailDiv = document.getElementById("cpv-detail-results");

    if (!cpvDetailDiv) {
        console.error("CPV detail container not found");
        return;
    }

    const detailsContainer = document.createElement("div");
    detailsContainer.className = "cpv-details-container";

    if (selectedCPV) {
        const table = document.createElement("table");
        table.className = "table table-striped";
        const tbody = document.createElement("tbody");

        selectedCPV.details.forEach((detail) => {
            const row = document.createElement("tr");
            row.innerHTML = `<td>${detail}</td>`;
            tbody.appendChild(row);
        });

        table.appendChild(tbody);
        detailsContainer.appendChild(table);
    }

    cpvDetailDiv.innerHTML = "";
    cpvDetailDiv.appendChild(detailsContainer);
}
window.showCPVDetails = showCPVDetails;

// Rest of the original functions remain the same
function select_cpv(name) {
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
            
            // If this CPV has an ID, show its details
            const cpv = cpvs_blueprint_1.find(c => c.name === result["name"]);
            if (cpv) {
                showCPVDetails(cpv.id);
            }
        }
    });
}
window.select_cpv = select_cpv;

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
window.gen_components_html = gen_components_html;

function get_blueprint_component_graph(blueprint_id) {
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
            const height = 400; // Increased height for better spacing

            const svg = d3.select("#blueprint_graph")
                .append("svg")
                .attr("width", width)
                .attr("height", height);

            // Create force simulation
            const simulation = d3.forceSimulation(data.nodes)
                .force("link", d3.forceLink(data.links)
                    .id(d => d.id)
                    .distance(150)) // Increased link distance
                .force("charge", d3.forceManyBody()
                    .strength(-300)) // Increased repulsion
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collision", d3.forceCollide().radius(50)); // Added collision detection

            const color = d3.scaleOrdinal(d3.schemeCategory10);

            // Create container for graph elements with zoom capability
            const container = svg.append("g");
            
            // Add zoom behavior
            svg.call(d3.zoom()
                .extent([[0, 0], [width, height]])
                .scaleExtent([0.5, 2])
                .on("zoom", (event) => {
                    container.attr("transform", event.transform);
                }));

            // Create arrow marker for directed edges
            svg.append("defs").append("marker")
                .attr("id", "arrow")
                .attr("viewBox", "0 -5 10 10")
                .attr("refX", 20)
                .attr("refY", 0)
                .attr("markerWidth", 6)
                .attr("markerHeight", 6)
                .attr("orient", "auto")
                .append("path")
                .attr("d", "M0,-5L10,0L0,5")
                .attr("fill", "#999");

            const link = container.append("g")
                .attr("class", "links")
                .selectAll("line")
                .data(data.links)
                .enter().append("line")
                .attr("class", "link")
                .attr("stroke-width", 2)
                .attr("stroke", "#999")
                .attr("marker-end", "url(#arrow)");

            // Create node groups
            const nodeGroup = container.append("g")
                .attr("class", "nodes")
                .selectAll("g")
                .data(data.nodes)
                .enter().append("g")
                .attr("class", "node-group")
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended));

            // Add circles to node groups
            const node = nodeGroup.append("circle")
                .attr("r", 20)
                .attr("fill", d => color(d.id));

            // Add labels with background
            const labels = nodeGroup.append("g")
                .attr("class", "label-group");

            // Add white background for labels
            labels.append("rect")
                .attr("class", "label-background")
                .attr("fill", "white")
                .attr("opacity", 0.8);

            // Add text labels
            const text = labels.append("text")
                .attr("dy", -30)
                .attr("text-anchor", "middle")
                .text(d => d.name)
                .each(function() {
                    const bbox = this.getBBox();
                    const parent = this.parentNode;
                    const rect = parent.querySelector("rect");
                    rect.setAttribute("x", bbox.x - 5);
                    rect.setAttribute("y", bbox.y - 2);
                    rect.setAttribute("width", bbox.width + 10);
                    rect.setAttribute("height", bbox.height + 4);
                });

            // Update positions on simulation tick
            simulation.on("tick", () => {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);

                nodeGroup
                    .attr("transform", d => `translate(${d.x},${d.y})`);
            });

            // Drag functions
            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }

            // Handle blueprint options
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
window.get_blueprint_component_graph = get_blueprint_component_graph;

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
window.gen_component_abstraction_html = gen_component_abstraction_html;

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
window.search_for_cpvs = search_for_cpvs;

function get_cpv_research_result_html(search_id, r)
{
    var container = $("<div><h4>Search " + search_id + "</h4></div>");
    if (r["cpv_inputs"] !== "None") {
        for (const cpv_input of r["cpv_inputs"]) {
            var cpv = $("<div></div>").text(`CPV: ${cpv_input.cpv_model}`);
            var cpv_path = $("<div></div>").text(`Path: ${cpv_input.cpv_path.path.join(", ")}`);
            // var input = $("<div></div>").text(`Input: ${r["cpv_inputs"][0].cpv_input}`);

            container.append(cpv);
            container.append(cpv_path);
            // container.append(input);
        }
    }
    if (r["tasks"] !== "None") {
        for (const [ta, tasks] of Object.entries(r.tasks)) {
            const tasks_div = $("<div></div>").text(`${ta} Tasks:`);
            const tasks_ul = $('<ul style="margin-bottom: 0"></ul>');
            for (const task of tasks) {
                const task_li = $("<li></li>").text(`${task.Description} [${task["Meta-Data"].join(", ")}]`);
                tasks_ul.append(task_li);
            }
            tasks_div.append(tasks_ul);
            container.append(tasks_div);
        }
    }
    var json_code = $('<code id="code" name="code" class="language-json" style="overflow-wrap: anywhere;" readonly></code>').html(
        hljs.highlight(JSON.stringify(r, null, 4), {'language': 'json'}).value
    );
    var json_pre = $('<pre class="code" style="background-color: #f3f3f3;"></pre>').append(json_code);
    var json_details = $('<details></details>').append($('<summary></summary>').text("Raw JSON")).append(json_pre);
    container.append(json_details);
    return container;
}
window.get_cpv_research_result_html = get_cpv_research_result_html;

function update_cpv_search_results() {
    if (autoUpdatePaused) {
        console.log("Auto-update paused");
        return; // Do nothing if auto-update is paused
    }

    const cpvResultsDiv = document.getElementById("cpv-search-results");
    if (!cpvResultsDiv) return;

    $.ajax({
        url: "/api/cpv_search_ids",
        success: function (result) {
            const cpvSearchIds = result["ids"];

            if (!cpvSearchIds.length) {
                cpvResultsDiv.innerHTML = "<span>No running searches.</span>";
                return;
            }

            cpvSearchIds.forEach((cpvSearchId) => {
                $.ajax({
                    url: "/api/cpv_search_result",
                    data: { id: cpvSearchId },
                    success: function (result) {
                        const elemId = `cpv-search-result-${cpvSearchId}`;
                        let resultDiv = document.getElementById(elemId);

                        if (!resultDiv) {
                            resultDiv = document.createElement("div");
                            resultDiv.id = elemId;
                            cpvResultsDiv.appendChild(resultDiv);
                        }

                        resultDiv.innerHTML = get_cpv_research_result_html(cpvSearchId, result);
                    },
                });
            });
        },
    });
}
window.update_cpv_search_results = update_cpv_search_results;

function add_blueprint(event) {
    const name = $("#new-blueprint-name").val();
    const blueprint = $("#new-blueprint-json").val();
    $.post({
        url: "/api/ingest_blueprint?name=" + encodeURIComponent(name),
        data: blueprint,
        contentType: "application/json",
        dataType: "json",
        success: (data) => {
            const option = $("<option></option>").attr("value", data.id).text(`${data.id}: ${data.name}`);
            $("#blueprint").append(option);
            alert(`added blueprint ${name} successfully`);
        },
        error: (xhr) => {
            alert(`adding blueprint failed: ${xhr.responseText}`);
        },
    })
}
window.add_blueprint = add_blueprint;

window.remove_hypothesis_component = function(elem) {
    elem.parentElement.remove();
    return false;
};

function make_hypothesis_component() {
    // janky lmao
    const old_hypo_comp = document.querySelector(".hypothesis-component");
    const new_hypo_comp = old_hypo_comp.cloneNode(true);
    new_hypo_comp.querySelector("input").value = "";
    return new_hypo_comp;
}

window.add_hypothesis_component = function(elem) {
    document.querySelector(".hypothesis-components")
        .appendChild(make_hypothesis_component());
    return false;
};

function make_hypothesis(name) {
    const link = $('<a href="#"></a>').text(name).on("click", () => select_cpv(`hypothesis/${name}`));
    return $('<li class="list-group-item"></li>').append(link);
}

window.add_hypothesis = function() {
    const name = $("#new-hypothesis-name").val();
    const components = $(".hypothesis-component input").map((i, e) => e.value).toArray();
    $.post({
        url: "/api/add_hypothesis?name=" + encodeURIComponent(name),
        data: JSON.stringify(components),
        contentType: "application/json",
        dataType: "json",
        success: (data) => {
            const li = make_hypothesis(name);
            $("#cpv-list").append(li);
            alert(`added hypothesis ${name} successfully`);
        },
        error: (xhr) => {
            alert(`adding hypothesis failed: ${xhr.responseText}`);
        },
    })
    return false;
};

$(document).ready(function() {
    //setInterval(update_cpv_search_results, 1000);
});
