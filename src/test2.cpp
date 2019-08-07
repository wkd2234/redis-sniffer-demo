#include <tins/tins.h>
#include <tins/tcp_ip/stream.h>
#include <tins/tcp_ip/stream_follower.h>
#include <iostream>
#include <stddef.h>
#include <string>

using namespace Tins;
using std::string;
using std::map;
using std::cout;
using std::endl;
using std::vector;
using std::to_string;
using std::ostringstream;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;


struct req_cmd {
    int len = 0;
    int snd_len = 0;
    int times = 0;
    int dur_time = 0;
    string cmd = "";
    string key = "";
};
map<string, req_cmd> global_req_cmd;

req_cmd get_req_cmd (const vector<string>& _req_cmd) {
    req_cmd req;

    if (_req_cmd.empty()) {
        return req;
    }

    int i = 0;
    for (auto it = _req_cmd.begin(); it != _req_cmd.end(); ++it) {
        if (i == 0) {
            req.len = stoi(*it);
        } else if (i == 1) {
            req.cmd = (*it);
        } else {
            req.key = (*it);
        }

        if (i++ == 2) {
            break;
        }

    }

    return req;
}

int string_split(const std::string& str, std::vector<std::string>& res, std::string sep = ",") {
    if (str.empty())  //字符串为空
    {
        return 0;
    }

    string tmp; //用来存储分割出来的临时字符串
    string::size_type pos_begin = str.find_first_not_of(sep); //定位第一个不是分隔符的地方
    string::size_type comma_pos = 0;

    while (pos_begin != std::string::npos)
    {
        comma_pos = str.find(sep, pos_begin); //不断地查找从pos_begin开始之后的分隔符位置
        if (comma_pos != std::string::npos)
        {
            tmp = str.substr(pos_begin, comma_pos - pos_begin);
            pos_begin = comma_pos + sep.length();
        }
        else
        {
            tmp = str.substr(pos_begin);
            pos_begin = comma_pos;
        }

        if (!tmp.empty())
        {
            res.push_back(tmp);
            tmp.clear();
        }
    }
    return res.size();
}

size_t counter(0);

bool count_packets(const PDU &) {
    counter++;
    // Always keep looping. When the end of the file is found, 
    // our callback will simply not be called again.
    return true;
}

string client_endpoint(const Stream& stream) {
    ostringstream output;
    output << stream.client_addr_v4();
    output << ":" << stream.server_port();

    return output.str();
}

string server_endpoint(const Stream& stream) {
    ostringstream output;
    output << stream.server_addr_v4(); output << ":" << stream.server_port();

    return output.str();
}

string stream_identifier(const Stream& stream) {
    ostringstream output;
    output << client_endpoint(stream) << " - " << server_endpoint(stream);

    return output.str();
}

vector<string> parse_RESP(const string& resp) {
    if (resp.empty()) {
        return {};
    }
    if (resp[0] != '*') {
        // unvalid
        return {};
    }
    vector<string> req;

    string req_len = to_string(resp.size());
    req.push_back(req_len);

    vector<string> lines;
    string_split(resp, lines, "\r\n");

    int cmd_len = 0;
    int next_len = 0;
    for (auto it = lines.begin(); it != lines.end(); ++it) {
        if ((*it)[0] == '*') {
            cmd_len = stoi((*it).substr(1));
            continue;
        }
        if (cmd_len == 0) {
            return {};
        }
        if ((*it)[0] == '$') {
            next_len = stoi((*it).substr(1));
            continue;
        }
        if (next_len != 0 && cmd_len-- != 0) {
            req.push_back((*it));
        }
    }

    return req;
}

void on_client_data(Stream& stream) {
    // Don't hold more than 3kb of data from the client's flow
}

void on_server_data(Stream& stream) {
    string svr_data(stream.server_payload().begin(), stream.server_payload().end());
    string cli_data(stream.client_payload().begin(), stream.client_payload().end());
    int dur_time = stream.last_seen().count() - stream.create_time().count();
    auto req = parse_RESP(cli_data);
    int snd_len = svr_data.size();

    req_cmd _req_cmd = get_req_cmd(req);
    string req_cmd_s = _req_cmd.cmd + " " + _req_cmd.key;
    if (_req_cmd.len != 0) {
        req_cmd r = global_req_cmd[req_cmd_s];
        r.len += _req_cmd.len;
        r.cmd = _req_cmd.cmd;
        r.key = _req_cmd.key;
        r.snd_len += snd_len;
        r.times += 1;
        r.dur_time += dur_time;
        global_req_cmd[req_cmd_s] = r;
    }
}

// When a connection is closed, this callback is executed.
void on_connection_closed(Stream& stream) {
    cout << "[+] Connection closed: " << stream_identifier(stream) << endl;
}

// When a new connection is captured, this callback will be executed.
void on_new_connection(Stream& stream) {
    if (stream.is_partial_stream()) {
        // We found a partial stream. This means this connection/stream had
        // been established before we started capturing traffic.
        //
        // In this case, we need to allow for the stream to catch up, as we
        // may have just captured an out of order packet and if we keep waiting
        // for the holes to be filled, we may end up waiting forever.
        //
        // Calling enable_recovery_mode will skip out of order packets that
        // fall withing the range of the given window size.
        // See Stream::enable_recover_mode for more information
        cout << "[+] New connection " << stream_identifier(stream) << endl;

        // Enable recovery mode using a window of 10kb
        stream.enable_recovery_mode(10 * 1024);
    }
    else {
        // Print some information about the new connection
        cout << "[+] New connection " << stream_identifier(stream) << endl;
    }

    // Now configure the callbacks on it.
    // First, we want on_client_data to be called every time there's new client data
    stream.client_data_callback(&on_client_data);
    // Same thing for server data, but calling on_server_data
    stream.server_data_callback(&on_server_data);
    stream.auto_cleanup_payloads(false);

    // When the connection is closed, call on_connection_closed
    stream.stream_closed_callback(&on_connection_closed);
}

int main() {
    // Construct the sniffer configuration object
    SnifferConfiguration config;

    // Only capture TCP traffic sent from/to the given port
    config.set_filter("tcp port 6379");
    // Now construct the stream follower
    StreamFollower follower;

    // We just need to specify the callback to be executed when a new
    // stream is captured. In this stream, you should define which callbacks
    // will be executed whenever new data is sent on that stream
    // (see on_new_connection)
    follower.new_stream_callback(&on_new_connection);

    // Allow following partial TCP streams (e.g. streams that were
    // open before the sniffer started running)
    follower.follow_partial_streams(true);

    // Now start capturing. Every time there's a new packet, call
    // follower.process_packet

    FileSniffer sniffer("/home/vagrant/test.pcap");
    sniffer.sniff_loop([&](PDU& packet) {
        follower.process_packet(packet);
        return true;
    });
    // std::cout << "There are " << counter << " packets in the pcap file\n";
    auto map_it = global_req_cmd.cbegin();

    while (map_it != global_req_cmd.cend()) {
        ++map_it;
    }
}
